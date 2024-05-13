// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


#include "ClientHello.h"
#include "../Network/Alerts.h"
#include "../Network/Results.h"

#include "../CryptoBase/Randomish.h"

#include "../CppBase/StIO.h"



ClientHello::ClientHello( void )
{
}


ClientHello::ClientHello( const ClientHello& in )
{
if( in.testForCopy )
  return;

throw "ClientHello copy constructor called.";
}



ClientHello::~ClientHello( void )
{
}




Uint32 ClientHello::parseBuffer(
                        const CharBuf& inBuf,
                        TlsMain& tlsMain,
                        EncryptTls& encryptTls )
{
try
{
msgBytes.copy( inBuf );

tlsMain.setClientHelloMsg( msgBytes );

// const Int32 last = msgBytes.getLast();

StIO::putS( "Parsing ClientHello." );

// handshake type at 0.
// length at 1, 2, and 3.

// Uint8 legacyHigh = msgBytes.getU8( 4 );
// Uint8 legacyLow = msgBytes.getU8( 5 );

CharBuf randBytes;

Int32 index = 6;
for( Int32 count = 0; count < 32; count++ )
  {
  randBytes.appendU8( msgBytes.getU8( index ));
  index++;
  }

tlsMain.setClientRandom( randBytes );

// if( index != 38 )
  // throw "ClientHello index != 38.";


// In the RFC:
// "In compatibility mode (see Appendix D.4),
// this field MUST be non-empty, so a client
// not offering a pre-TLS 1.3 session MUST
// generate a new 32-byte value.  This value
// need not be random but SHOULD be
// unpredictable to avoid implementations
// fixating on a specific value (also known
// as ossification).  Otherwise, it MUST be
// set as a zero-length vector (i.e., a
// zero-valued single byte length field)."

const Uint8 sessionIDLength = msgBytes.getU8( 38 );

StIO::printF( "sessionIDLength: " );
StIO::printFUD( sessionIDLength );
StIO::putLF();

if( sessionIDLength > 32 )
  {
  StIO::putS( "sessionIDLength is too long." );
  return Alerts::DecodeError;
  }

// It needs to keep the session ID so the
// server can send it back.

index = 39;

CharBuf sessionID;
for( Uint32 countID = 0;
           countID < sessionIDLength; countID++ )
  {
  sessionID.appendU8( msgBytes.getU8( index ));
  index++;
  }

tlsMain.setSessionIDLegacy( sessionID );

Uint32 cipherLength = msgBytes.getU8( index );
index++;
cipherLength <<= 8;
cipherLength |= msgBytes.getU8( index );
index++;

StIO::printF( "cipherLength: " );
StIO::printFUD( cipherLength );
StIO::putLF();

// How long should this be?
if( cipherLength > 16000 )
  {
  StIO::putS( "cipherLength is too long." );
  return Alerts::DecodeError;
  }

bool standardCipherFound = false;

const Uint32 maxCipher = cipherLength / 2;
for( Uint32 count = 0; count < maxCipher; count++ )
  {
  Uint8 cipherHigh = msgBytes.getU8( index );
  index++;

  Uint8 cipherLow = msgBytes.getU8( index );
  index++;

  // The hash that is shown in something like
  // TLS_AES_128_GCM_SHA256 is used in the Key
  // Derivation function.

  // This is the only cipher I have working now.
  // "A TLS-compliant application MUST implement
  // TLS_AES_128_GCM_SHA256"
  // See RFC 8446 Appendix B for these
  // ciphersuites.
  // This is a list of AEAD algorithms, and the
  // hash for HKDF, that the client wants to use.
  // TLS_AES_128_GCM_SHA256       | {0x13,0x01} |
  // TLS_AES_256_GCM_SHA384       | {0x13,0x02} |
  // TLS_CHACHA20_POLY1305_SHA256 | {0x13,0x03} |
  // TLS_AES_128_CCM_SHA256       | {0x13,0x04} |
  // TLS_AES_128_CCM_8_SHA256     | {0x13,0x05} |


  // TLS_AES_128_GCM_SHA256     | {0x13,0x01} |

  if( (cipherHigh == 0x13) &&
      (cipherLow == 0x01))
    standardCipherFound = true;

  }

if( !standardCipherFound )
  {
  StIO::putS( "AES 128 standard was not found." );
  // What alert should this be?
  return Alerts::DecodeError;
  }

Uint8 compressionLength = msgBytes.getU8( index );
index++;

if( compressionLength == 1 )
  {
  Uint8 compressionValue = msgBytes.getU8( index );
  index++;
  if( compressionValue != 0 )
    {
    StIO::printF( "compressionValue is bad: " );
    StIO::printFUD( compressionValue );
    StIO::putLF();

    return Alerts::IllegalParameter;
    }
  }
else
  {
  // The minimum is 1 here:
  // opaque legacy_compression_methods&lt;
  //                             1..2^8-1&gt;;

  StIO::putS(
      "Compression method should have 1 byte." );

  return Alerts::IllegalParameter;
  }


// Now for the extensions.

StIO::printF( "index for extension is: " );
StIO::printFD( index );
StIO::putLF();

ExtenList extList;
Uint32 result = extList.setFromMsg(
                         msgBytes,
                         index,
                         tlsMain,
                         false, // isServerMsg.
                         encryptTls );
StIO::putS( "\nAfter extensions.\n" );

return result;

}
catch( const char* in )
  {
  StIO::putS(
      "Exception in ClientHello.parseBuffer.\n" );
  StIO::putS( in );
  return Alerts::DecodeError;
  }

catch( ... )
  {
  StIO::putS(
       "Exception in ClientHello.parseBuffer." );
  return Alerts::DecodeError;
  }
}



void ClientHello::makeHelloBuf(
                       CharBuf& outBuf,
                       TlsMain& tlsMain,
                       EncryptTls& encryptTls )
{
StIO::putS( "Top of makeHelloBuf." );

CharBuf randBytes;
Randomish::makeRandomBytes( randBytes, 32 + 10 );

CharBuf randBuf;
for( Int32 count = 0; count < 32; count++ )
  {
  outBuf.appendU8( randBytes.getU8( count ));
  randBuf.appendU8( randBytes.getU8( count ));
  }

tlsMain.setClientRandom( randBuf );

// This is set to 32 bytes for compatibility.
CharBuf sessionIDBuf;
outBuf.appendU8( 32 ); // Legacy session ID length.

Randomish::makeRandomBytes( randBytes, 32 + 10 );
for( Int32 count = 0; count < 32; count++ )
  {
  outBuf.appendU8( randBytes.getU8( count ));
  sessionIDBuf.appendU8(
                      randBytes.getU8( count ));
  }

// The client makes the Session ID and the
// server has to echo it back.
tlsMain.setSessionIDLegacy( sessionIDBuf );


// Appendix B of RFC 8446 for TLS 1.3 shows
// the cipher suites.

outBuf.appendU8( 0 ); // Length high byte.
outBuf.appendU8( 2 ); // Low byte.

// TLS_AES_128_GCM_SHA256       | {0x13,0x01} |

// Normally this would be a list of ciphersuites
// but I only have one ciphersuite working so far.
outBuf.appendU8( 0x13 );
outBuf.appendU8( 0x01 );

outBuf.appendU8( 0x01 ); // Compression length.
outBuf.appendU8( 0x00 ); // Compression none.

// Extensions go after compression method.


// See RFC 7748 Section 6.1 for what is
// sent here.

Integer k;
CharBuf privKeyBuf;
tlsMain.mCurve.makeRandExponentK( k, privKeyBuf );

Integer U;
U.setFromLong48( 9 );

Integer pubKey;
tlsMain.mCurve.montLadder1(
                     pubKey, U, k,
                     tlsMain.intMath,
                     tlsMain.mod );

encryptTls.setClientPrivKey( k );
encryptTls.setClientPubKey( pubKey );

CharBuf extenListBuf;
extenList.makeClHelloBuf( extenListBuf,
                          tlsMain,
                          encryptTls );

outBuf.appendCharBuf( extenListBuf );
}
