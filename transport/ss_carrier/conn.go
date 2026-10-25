package ss_carrier

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"net"
	"time"

	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/transport/socks"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/ioutil"
	"github.com/floating-cat/heteroglossia/util/log"
	"github.com/floating-cat/heteroglossia/util/randutil"
	pool "github.com/libp2p/go-buffer-pool"
)

type conn struct {
	*net.TCPConn
	accessAddr   *transport.SocketAddress
	preSharedKey []byte

	clientSalt  []byte
	saltSize    int
	aeadWriter  cipher.AEAD
	nonceWriter []byte

	aeadReader   cipher.AEAD
	nonceReader  []byte
	readerBuf    []byte
	aeadOverhead int

	isClient             bool
	hasWriteFirstPayload bool
	hasReadFirstPayload  bool
	serverSideSaltPool   *saltPool[string]
}

var _ net.Conn = (*conn)(nil)
var _ io.ReaderFrom = (*conn)(nil)
var _ io.WriterTo = (*conn)(nil)
var _ ioutil.CloseWriter = (*conn)(nil)

func newClientConn(tcpConn *net.TCPConn, accessAddr *transport.SocketAddress,
	preSharedKey []byte, salt []byte, aeadOverhead int) *conn {
	return &conn{TCPConn: tcpConn, accessAddr: accessAddr,
		preSharedKey: preSharedKey, clientSalt: salt, saltSize: len(salt), aeadOverhead: aeadOverhead,
		isClient: true}
}

func newServerConn(tcpConn *net.TCPConn, preSharedKey []byte, aeadOverhead int, serverSideSaltPool *saltPool[string]) *conn {
	// salt has the same length as the pre-shared key
	return &conn{TCPConn: tcpConn, preSharedKey: preSharedKey, saltSize: len(preSharedKey), aeadOverhead: aeadOverhead,
		isClient: false, serverSideSaltPool: serverSideSaltPool}
}

const (
	maxPaddingLen = 900
	// A payload chunk can have up to 0xFFFF (65,535) bytes of unencrypted payload.
	// https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md#312-format
	maxChunkSize           = 65535
	clientStreamHeaderType = 0
	serverStreamHeaderType = 1

	lenFieldSize          = 2
	typeWithTimestampSize = 1 + 8
	reqFixedLenHeaderSize = typeWithTimestampSize + lenFieldSize
)

/*
https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md#312-format
Request stream
+--------+------------------------+---------------------------+------------------------+---------------------------+---+
|  salt  | encrypted header chunk |  encrypted header chunk   | encrypted length chunk |  encrypted payload chunk  |...|
+--------+------------------------+---------------------------+------------------------+---------------------------+---+
| 16/32B |   11B + 16B AEAD tag   | variable length + 16B tag |  2B length + 16B tag   | variable length + 16B tag |...|
+--------+------------------------+---------------------------+------------------------+---------------------------+---+

Response stream
+--------+------------------------+---------------------------+------------------------+---------------------------+---+
|  salt  | encrypted header chunk |  encrypted payload chunk  | encrypted length chunk |  encrypted payload chunk  |...|
+--------+------------------------+---------------------------+------------------------+---------------------------+---+
| 16/32B | 27/43B + 16B AEAD tag  | variable length + 16B tag |  2B length + 16B tag   | variable length + 16B tag |...|
+--------+------------------------+---------------------------+------------------------+---------------------------+---+

+----------------+
|  length chunk  |
+----------------+
| u16 big-endian |
+----------------+

+---------------+
| payload chunk |
+---------------+
|   variable    |
+---------------+
*/

func (c *conn) Write(p []byte) (n int, err error) {
	count, err := c.ReadFrom(bytes.NewReader(p))
	return int(count), err
}

func (c *conn) writeClientFirstPayload(payload []byte) error {
	payloadLen := len(payload)
	var paddingLen, reqPaddingAndPayloadLen int
	if payloadLen <= 0 {
		// In a request header, either initial payload or padding MUST be
		// present. When making a request header, if payload is not available,
		// add non-zero random length padding.
		// https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md#313-detection-prevention
		paddingLen = rand.N(maxPaddingLen) + 1
		reqPaddingAndPayloadLen = paddingLen
	} else {
		paddingLen = 0
		reqPaddingAndPayloadLen = payloadLen
	}

	reqPaddingOrPayloadStart := socks.SOCKSLikeAddrSizeInBytes(c.accessAddr) + lenFieldSize
	reqVarLenHeaderLen := reqPaddingOrPayloadStart + reqPaddingAndPayloadLen
	reqVarLenHeaderEncryptedStart := c.saltSize + reqFixedLenHeaderSize + c.aeadOverhead
	reqHeaderEncryptedBs := pool.Get(reqVarLenHeaderEncryptedStart + reqVarLenHeaderLen + c.aeadOverhead)
	defer pool.Put(reqHeaderEncryptedBs)

	// Request fixed-length header
	// +------+------------------+--------+
	// | type |     timestamp    | length |
	// +------+------------------+--------+
	// |  1B  | u64be unix epoch |  u16be |
	// +------+------------------+--------+
	reqFixedLenHeaderBs := reqHeaderEncryptedBs[c.saltSize:reqVarLenHeaderEncryptedStart]
	reqFixedLenHeaderBuf := bytes.NewBuffer(reqFixedLenHeaderBs[:0])
	reqFixedLenHeaderBuf.WriteByte(clientStreamHeaderType)
	err := binary.Write(reqFixedLenHeaderBuf, binary.BigEndian, uint64(time.Now().Unix()))
	if err != nil {
		return errors.WithStack(err)
	}
	err = binary.Write(reqFixedLenHeaderBuf, binary.BigEndian, uint16(reqVarLenHeaderLen))
	if err != nil {
		return errors.WithStack(err)
	}

	// Request variable-length header
	// +------+----------+-------+----------------+----------+-----------------+
	// | ATYP |  address |  port | padding length |  padding | initial payload |
	// +------+----------+-------+----------------+----------+-----------------+
	// |  1B  | variable | u16be |     u16be      | variable |    variable     |
	// +------+----------+-------+----------------+----------+-----------------+
	reqVarLenHeaderBs := reqHeaderEncryptedBs[reqVarLenHeaderEncryptedStart:]
	reqVarLenHeaderBuf := bytes.NewBuffer(reqVarLenHeaderBs[:0])
	socks.WriteSOCKSLikeAddr(reqVarLenHeaderBuf, c.accessAddr)
	err = binary.Write(reqVarLenHeaderBuf, binary.BigEndian, uint16(paddingLen))
	if err != nil {
		return errors.WithStack(err)
	}
	if payloadLen <= 0 {
		padding := reqVarLenHeaderBuf.AvailableBuffer()[:paddingLen]
		_ = randutil.RandBytes(padding)
		reqVarLenHeaderBuf.Write(padding)
	} else {
		reqVarLenHeaderBuf.Write(payload[:payloadLen])
	}

	copy(reqHeaderEncryptedBs, c.clientSalt)
	clientAEAD, err := aeadCipher(c.preSharedKey, c.clientSalt)
	if err != nil {
		return err
	}
	c.setAEADWriter(clientAEAD)
	c.encryptInPlace(reqFixedLenHeaderBuf.Bytes())
	c.encryptInPlace(reqVarLenHeaderBuf.Bytes())

	_, err = c.TCPConn.Write(reqHeaderEncryptedBs)
	return errors.WithStack(err)
}

/*
First response stream
+--------+------------------------+---------------------------+
|  salt  | encrypted header chunk |  encrypted payload chunk  |
+--------+------------------------+---------------------------+
| 16/32B |    27/43B + 16B tag    | variable length + 16B tag |
+--------+------------------------+---------------------------+
*/
func (c *conn) writeServerFirstPayload(payload []byte) error {
	payloadLen := len(payload)
	respPayloadEncryptedStart := c.saltSize + reqFixedLenHeaderSize + c.saltSize + c.aeadOverhead
	respSaltWithFixedLenHeaderAndPayloadEncryptedBs := pool.Get(respPayloadEncryptedStart + payloadLen + c.aeadOverhead)
	defer pool.Put(respSaltWithFixedLenHeaderAndPayloadEncryptedBs)
	respSaltWithFixedLenHeaderAndPayloadEncryptedBuf := bytes.NewBuffer(respSaltWithFixedLenHeaderAndPayloadEncryptedBs[:0])
	serverSalt := generateSalt(c.preSharedKey)
	respSaltWithFixedLenHeaderAndPayloadEncryptedBuf.Write(serverSalt)

	// Response fixed-length header
	// +------+------------------+----------------+--------+
	// | type |     timestamp    |  request salt  | length |
	// +------+------------------+----------------+--------+
	// |  1B  | u64be unix epoch |     16/32B     |  u16be |
	// +------+------------------+----------------+--------+
	respSaltWithFixedLenHeaderAndPayloadEncryptedBuf.WriteByte(serverStreamHeaderType)
	err := binary.Write(respSaltWithFixedLenHeaderAndPayloadEncryptedBuf, binary.BigEndian, uint64(time.Now().Unix()))
	if err != nil {
		return errors.WithStack(err)
	}
	respSaltWithFixedLenHeaderAndPayloadEncryptedBuf.Write(c.clientSalt)
	err = binary.Write(respSaltWithFixedLenHeaderAndPayloadEncryptedBuf, binary.BigEndian, uint16(payloadLen))
	if err != nil {
		return errors.WithStack(err)
	}
	copy(respSaltWithFixedLenHeaderAndPayloadEncryptedBuf.AvailableBuffer()[c.aeadOverhead:c.aeadOverhead+payloadLen], payload)

	serverAEAD, err := aeadCipher(c.preSharedKey, serverSalt)
	if err != nil {
		return err
	}
	c.setAEADWriter(serverAEAD)

	respFixedLenHeaderEncryptedBs := respSaltWithFixedLenHeaderAndPayloadEncryptedBs[c.saltSize:]
	c.encryptInPlace(respFixedLenHeaderEncryptedBs[:reqFixedLenHeaderSize+c.saltSize])
	respPayloadEncryptedBs := respSaltWithFixedLenHeaderAndPayloadEncryptedBs[respPayloadEncryptedStart:]
	c.encryptInPlace(respPayloadEncryptedBs[:payloadLen])
	_, err = c.TCPConn.Write(respSaltWithFixedLenHeaderAndPayloadEncryptedBs)
	if err != nil {
		return err
	}
	return err
}

func (c *conn) Read(p []byte) (n int, err error) {
	// Return early otherwise a zero-length read would read the next chunk.
	if len(p) == 0 {
		return 0, nil
	}
	return c.readOrWriteTo(p, nil)
}

func (c *conn) readOrWriteTo(b []byte, w io.Writer) (n int, err error) {
	if c.isClient && !c.hasReadFirstPayload {
		c.hasReadFirstPayload = true
		return c.readServerFirstPayload(b, w)
	}

	if len(c.readerBuf) != 0 {
		if w != nil {
			n, err := ioutil.Write(w, c.readerBuf)
			c.readerBuf = c.readerBuf[n:]
			return n, err
		}
		n = copy(b, c.readerBuf)
		c.readerBuf = c.readerBuf[n:]
		return n, nil
	}

	// Stream chunk
	// +------------------------+---------------------------+
	// | encrypted length chunk |  encrypted payload chunk  |
	// +------------------------+---------------------------+
	// |   2B + 16B AEAD tag    | variable length + 16B tag |
	// +------------------------+---------------------------+
	payloadLenEncryptedSize := lenFieldSize + c.aeadOverhead
	_, payloadLenEncryptedBs, err := ioutil.ReadN(c.TCPConn, payloadLenEncryptedSize)
	if err != nil {
		return 0, err
	}
	err = c.decryptInPlace(payloadLenEncryptedBs)
	if err != nil {
		return 0, err
	}
	payloadLen := int(binary.BigEndian.Uint16(payloadLenEncryptedBs))
	return c.copyReadPayloadEncrypted(b, w, payloadLen)
}

func (c *conn) readServerFirstPayload(b []byte, w io.Writer) (int, error) {
	c.hasReadFirstPayload = true
	respSaltWithFixedLenHeaderEncryptedBs := pool.Get(c.saltSize + reqFixedLenHeaderSize + c.saltSize + c.aeadOverhead)
	defer pool.Put(respSaltWithFixedLenHeaderEncryptedBs)
	_, err := ioutil.ReadOnceExpectFull(c.TCPConn, respSaltWithFixedLenHeaderEncryptedBs)
	if err != nil {
		return 0, err
	}

	serverAEAD, err := aeadCipher(c.preSharedKey, respSaltWithFixedLenHeaderEncryptedBs[:c.saltSize])
	if err != nil {
		return 0, err
	}
	c.setAEADReader(serverAEAD)

	respFixedLenHeaderEncryptedBs := respSaltWithFixedLenHeaderEncryptedBs[c.saltSize:]
	err = c.decryptInPlace(respFixedLenHeaderEncryptedBs)
	if err != nil {
		return 0, err
	}
	respPayloadLen, err := c.validateFixedHeaderAndReturnLen(respFixedLenHeaderEncryptedBs)
	if err != nil {
		return 0, err
	}
	return c.copyReadPayloadEncrypted(b, w, respPayloadLen)
}

func (c *conn) readClientFirstPayload() error {
	c.hasReadFirstPayload = true
	var err error
	defer func() {
		if err != nil {
			// To consistently send RST even when the received buffer is empty,
			// set 'SO_LINGER' to true with a zero timeout, then close the socket.
			// https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md#313-detection-prevention
			err = c.TCPConn.SetLinger(0)
			if err != nil {
				log.WarnWithError("fail to set SO_LINGER", err)
			}
		}
	}()
	reqSaltWithFixedLenHeaderEncryptedSize := c.saltSize + reqFixedLenHeaderSize + c.aeadOverhead
	reqSaltWithFixedLenHeaderEncryptedBs := pool.Get(reqSaltWithFixedLenHeaderEncryptedSize)
	defer pool.Put(reqSaltWithFixedLenHeaderEncryptedBs)
	_, err = ioutil.ReadOnceExpectFull(c.TCPConn, reqSaltWithFixedLenHeaderEncryptedBs)
	if err != nil {
		return err
	}

	// Copy the salt out of the pooled buffer because it is referenced later.
	c.clientSalt = bytes.Clone(reqSaltWithFixedLenHeaderEncryptedBs[:c.saltSize])
	clientSaltStr := string(c.clientSalt)
	ok := c.serverSideSaltPool.checkAndAdd(clientSaltStr)
	if !ok {
		return errors.New("replay detected due to repeated salt found")
	}
	clientAEAD, err := aeadCipher(c.preSharedKey, reqSaltWithFixedLenHeaderEncryptedBs[:c.saltSize])
	if err != nil {
		return err
	}
	c.setAEADReader(clientAEAD)

	reqFixedLenHeaderEncryptedBs := reqSaltWithFixedLenHeaderEncryptedBs[c.saltSize:]
	err = c.decryptInPlace(reqFixedLenHeaderEncryptedBs)
	if err != nil {
		return err
	}
	reqVarLenHeaderLen, err := c.validateFixedHeaderAndReturnLen(reqFixedLenHeaderEncryptedBs)
	if err != nil {
		return err
	}

	reqVarLenHeaderEncryptedBs := pool.Get(reqVarLenHeaderLen + c.aeadOverhead)
	defer pool.Put(reqVarLenHeaderEncryptedBs)
	_, err = ioutil.ReadFull(c.TCPConn, reqVarLenHeaderEncryptedBs)
	if err != nil {
		return err
	}
	err = c.decryptInPlace(reqVarLenHeaderEncryptedBs)
	if err != nil {
		return err
	}
	reqVarLenHeaderReader := bytes.NewBuffer(reqVarLenHeaderEncryptedBs[0 : len(reqVarLenHeaderEncryptedBs)-c.aeadOverhead])
	accessAddr, err := socks.ReadSOCKS5Address(reqVarLenHeaderReader)
	if err != nil {
		return err
	}
	c.accessAddr = accessAddr

	// Servers MUST reject the request if the variable-length header chunk
	// does not contain payload and the padding length is 0. Servers MUST
	// enforce that the request header (including padding) does not extend
	// beyond the header chunks.
	// https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md#312-format
	if reqVarLenHeaderReader.Len() <= lenFieldSize {
		return errors.New("client payload and the padding length are both 0 in request variable-length header")
	}
	_, paddingLenBs, err := ioutil.ReadN(reqVarLenHeaderReader, lenFieldSize)
	if err != nil {
		return err
	}
	paddingLen := int(binary.BigEndian.Uint16(paddingLenBs))
	remainLen := reqVarLenHeaderReader.Len()
	if remainLen < paddingLen {
		return errors.Newf("expect %v padding byte(s), but only have %v remain bytes in request header",
			paddingLen, remainLen)
	}
	_, err = c.copyReadPayload([]byte{}, reqVarLenHeaderReader.Bytes()[paddingLen:])
	return err
}

func (c *conn) copyReadPayloadEncrypted(b []byte, w io.Writer, payloadLen int) (int, error) {
	payloadEncryptedBs := pool.Get(payloadLen + c.aeadOverhead)
	defer pool.Put(payloadEncryptedBs)
	_, err := ioutil.ReadFull(c.TCPConn, payloadEncryptedBs)
	if err != nil {
		return 0, err
	}
	err = c.decryptInPlace(payloadEncryptedBs)
	if err != nil {
		return 0, err
	}
	if w != nil {
		return ioutil.Write(w, payloadEncryptedBs[:payloadLen])
	}
	return c.copyReadPayload(b, payloadEncryptedBs[:payloadLen])
}

func (c *conn) copyReadPayload(b []byte, payloadBs []byte) (int, error) {
	n := copy(b, payloadBs)
	payloadLen := len(payloadBs)
	if n < payloadLen {
		readerBuf := make([]byte, payloadLen-n)
		copy(readerBuf, payloadBs[n:payloadLen])
		c.readerBuf = readerBuf
	}
	return n, nil
}

/*
Request fixed-length header
+------+------------------+--------+
| type |     timestamp    | length |
+------+------------------+--------+
|  1B  | u64be unix epoch |  u16be |
+------+------------------+--------+

Response fixed-length header
+------+------------------+----------------+--------+
| type |     timestamp    |  request salt  | length |
+------+------------------+----------------+--------+
|  1B  | u64be unix epoch |     16/32B     |  u16be |
+------+------------------+----------------+--------+
*/
func (c *conn) validateFixedHeaderAndReturnLen(fixedLenHeaderBs []byte) (int, error) {
	var streamHeaderType byte
	if c.isClient {
		streamHeaderType = serverStreamHeaderType
	} else {
		streamHeaderType = clientStreamHeaderType
	}
	if fixedLenHeaderBs[0] != streamHeaderType {
		return 0, errors.Newf("invalid stream header type '%v', '%v expect",
			fixedLenHeaderBs[0], streamHeaderType)
	}
	err := validateUnixTimeInRange(fixedLenHeaderBs[1:])
	if err != nil {
		return 0, err
	}

	var lenStart int
	if c.isClient {
		lenStart = typeWithTimestampSize + c.saltSize
		receivedClientSalt := fixedLenHeaderBs[typeWithTimestampSize:lenStart]
		if !bytes.Equal(c.clientSalt, receivedClientSalt) {
			return 0, errors.New("incorrect client salt in response header")
		}
	} else {
		lenStart = typeWithTimestampSize
	}

	lenBs := fixedLenHeaderBs[lenStart:]
	return int(binary.BigEndian.Uint16(lenBs)), nil
}

func (c *conn) ReadFrom(r io.Reader) (n int64, err error) {
	payloadStart := lenFieldSize + c.aeadOverhead
	maxPayloadReadSize := payloadStart + maxChunkSize + c.aeadOverhead
	maxPayloadReadBs := pool.Get(maxPayloadReadSize)
	defer pool.Put(maxPayloadReadBs)

	if !c.hasWriteFirstPayload {
		c.hasWriteFirstPayload = true
		// The initial payload is carried inside the first variable-length
		// header chunk, including the request address and padding-length
		// field on the ss client side. Therefore, we need to subtract these
		// when reading the payload from the request side.
		// request payload -> ss client -> ss server
		var maxFirstPayloadSize int
		if c.isClient {
			maxFirstPayloadSize = maxChunkSize - socks.SOCKSLikeAddrSizeInBytes(c.accessAddr) - lenFieldSize
		} else {
			maxFirstPayloadSize = maxChunkSize
		}
		count, err := r.Read(maxPayloadReadBs[:maxFirstPayloadSize])
		n += int64(count)
		if err != nil && !errors.IsIoEof(err) {
			return n, err
		}
		if c.isClient {
			err = c.writeClientFirstPayload(maxPayloadReadBs[:count])
		} else {
			err = c.writeServerFirstPayload(maxPayloadReadBs[:count])
		}
		if err != nil {
			return n, err
		}
	}

	for {
		count, err := r.Read(maxPayloadReadBs[payloadStart : payloadStart+maxChunkSize])
		n += int64(count)
		// Write the bytes before checking err, since a reader may return its
		// last bytes together with io.EOF.
		if count > 0 {
			binary.BigEndian.PutUint16(maxPayloadReadBs, uint16(count))
			c.encryptInPlace(maxPayloadReadBs[:lenFieldSize])
			c.encryptInPlace(maxPayloadReadBs[payloadStart : payloadStart+count])

			_, werr := c.TCPConn.Write(maxPayloadReadBs[:payloadStart+count+c.aeadOverhead])
			if werr != nil {
				if errors.IsIoEof(err) {
					err = nil
				}
				return n, errors.Append(err, werr)
			}
		}
		if err != nil {
			if errors.IsIoEof(err) {
				return n, nil
			}
			return n, errors.WithStack(err)
		}
	}
}

func (c *conn) WriteTo(w io.Writer) (n int64, err error) {
	for {
		count, err := c.readOrWriteTo(nil, w)
		n += int64(count)
		if err != nil {
			if errors.IsIoEof(err) {
				return n, nil
			}
			return n, err
		}
	}
}

func (c *conn) setAEADReader(aead cipher.AEAD) {
	c.aeadReader = aead
	c.nonceReader = make([]byte, aead.NonceSize())
}

func (c *conn) setAEADWriter(aead cipher.AEAD) {
	c.aeadWriter = aead
	c.nonceWriter = make([]byte, aead.NonceSize())
}

func (c *conn) encrypt(dst []byte, src []byte) {
	c.aeadWriter.Seal(dst, c.nonceWriter, src, nil)
	incNonce(c.nonceWriter)
}

func (c *conn) encryptInPlace(src []byte) {
	c.encrypt(src[:0], src)
}

func (c *conn) decryptInPlace(src []byte) error {
	_, err := c.aeadReader.Open(src[:0], c.nonceReader, src, nil)
	if err != nil {
		return errors.WithStack(err)
	}
	incNonce(c.nonceReader)
	return nil
}

func incNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}
