// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


#include "HandshakeCl.h"
#include "../Network/Alerts.h"
#include "../Network/Results.h"
#include "../Certificate/CertMesg.h"
#include "../Certificate/CertVerMesg.h"
#include "../Network/FinishedMesg.h"
#include "../CryptoBase/Randomish.h"
#include "../CppBase/StIO.h"




HandshakeCl::HandshakeCl( void )
{
circBufIn.setSize( 1024 * 512 );
}


HandshakeCl::HandshakeCl( const HandshakeCl& in )
{
if( in.testForCopy )
  return;

throw "HandshakeCl copy constructor called.";
}


HandshakeCl::~HandshakeCl( void )
{
}



Uint32 HandshakeCl::accumByte( Uint8 toAdd )
{
allBytes.appendU8( toAdd );
Int32 last = allBytes.getLast();

if( last == 1 )
  {
  recordType = allBytes.getU8( 0 );

  // StIO::printF( "accumByte HandshakeCl type: " );
  // StIO::printFUD( recordType );
  // StIO::putLF();

  return Results::Continue; // Keep adding bytes.
  }

if( last == 4 )
  {
  if( recordType ==
             Handshake::HelloRequestRESERVED )
    {
    // This is sent by older versions.
    // A hello request is empty.
    recLength = allBytes.getU8( 1 );
    StIO::printF( "First byte: " );
    StIO::printFD( recLength );
    StIO::putLF();

    recLength = allBytes.getU8( 2 );
    StIO::printF( "Second byte: " );
    StIO::printFD( recLength );
    StIO::putLF();

    recLength = allBytes.getU8( 3 );
    StIO::printF( "Third byte: " );
    StIO::printFD( recLength );
    StIO::putLF();

    recLength = 0;
    return Results::Done;
    }

  // A TlsOuterRec has a length with 2 bytes and
  // a handshake has a length with 3 bytes.  So a
  // handshake message can be a lot longer than
  // one TlsOuterRec.

  recLength = allBytes.getU8( 1 );
  recLength <<= 8;
  recLength |= allBytes.getU8( 2 );
  recLength <<= 8;
  recLength |= allBytes.getU8( 3 );

  // RFC 8446 Section 5.1:

  if( recLength == 0 )
    {
    StIO::putS( "Handshake  length is zero." );
    return Alerts::DecodeError;
    }

  // What is too long here?
  if( recLength > 0xFFFFFF ) // What max?
    {
    StIO::printF(
           "Handshake recLength is too big." );
    return Alerts::RecordOverflow;
    }

  // StIO::printF( "Handshake record length: " );
  // StIO::printFD( recLength );
  // StIO::putLF();

  return Results::Continue;
  }

if( last > 4 )
  {
  // One type byte and 3 bytes for length is
  // 4 bytes extra.
  if( last >= (recLength + 4) )
    return Results::Done;

  }

return Results::Continue;
}




Uint32 HandshakeCl::parseMessage(
                      TlsMain& tlsMain,
                      Uint8& MsgID,
                      EncryptTls& encryptTls )
{
StIO::putS( "Doing HandShakeCl parseMessage()." );

// const Int32 last = allBytes.getLast();
// StIO::printF( "HandshakeCl parse last: " );
// StIO::printFD( last );
// StIO::putLF();

recordType = allBytes.getU8( 0 );

if( !Handshake::recordTypeGood( recordType ))
  {
  StIO::putS(
       "The HandshakeCl record type is bad." );
  return Alerts::UnexpectedMessage;
  }

if( recordType ==
           Handshake::HelloRequestRESERVED )
  {
  StIO::putS( "\nHelloRequestRESERVED." );
  return Results::Done;
  }

if( recordType == Handshake::ClientHelloID )
  {
  Uint32 parseResult = clientHello.parseBuffer(
                    allBytes, tlsMain,
                    encryptTls );

  if( parseResult < Results::AlertTop )
    return parseResult;

  tlsMain.setClientHelloMsg( allBytes );

  MsgID = Handshake::ClientHelloID;
  return Results::Done;
  }

if( recordType == Handshake::ServerHelloID )
  {
  StIO::putS( "Got a ServerHelloID" );
  Uint32 parseResult = serverHello.parseBuffer(
              allBytes, tlsMain, encryptTls );

  if( parseResult < Results::AlertTop )
    return parseResult;

  tlsMain.setServerHelloMsg( allBytes );

  MsgID = Handshake::ServerHelloID;
  return Results::Done;
  }

if( recordType == Handshake::NewSessionTicketID )
  {
  StIO::putS( "NewSessionTicketID" );

  // StIO::putLF();
  // StIO::putS( "NewSessionTicketID hex:" );
  // allBytes.showHex();
  // StIO::putLF();

  MsgID = Handshake::NewSessionTicketID;
  return Results::Done;
  }

if( recordType == Handshake::EndOfEarlyDataID )
  {
  StIO::putS( "EndOfEarlyDataID" );

  MsgID = Handshake::EndOfEarlyDataID;
  return Results::Done;
  }

if( recordType ==
           Handshake::EncryptedExtensionsID )
  {
  StIO::putS( "EncryptedExtensionsID" );

  tlsMain.setEncExtenMsg( allBytes );

  if( Handshake::EncryptedExtensionsID !=
                         allBytes.getU8( 0 ))
    throw "EncryptedExtensionsID first byte.";

  // Three length bytes.
  // allBytes.getU8( 1 ))
  // allBytes.getU8( 2 ))
  // allBytes.getU8( 3 ))

  // Handshake messages don't have the
  // legacy version number.
  // The ProtocolVersion at the top of a
  // ClientHello is part of that ClientHello
  // message.  But a handshake message is just
  // a type and three length bytes.

  ExtenList extenList;
  // allBytes has the whole handshake message,
  // so the index for extensions is at 4.
  Uint32 result = extenList.setFromMsg(
                          allBytes, 4,
                          tlsMain, true,
                          encryptTls  );

  if( result < Results::AlertTop )
    return result;

  MsgID = Handshake::EncryptedExtensionsID;
  return Results::Done;
  }

if( recordType == Handshake::CertificateID )
  {
  StIO::putLF();
  StIO::putS( "CertificateID" );

  tlsMain.setCertificateMsg( allBytes );

  CharBuf certBuf;
  Int32 max = allBytes.getLast();

  // Start at 4, past the handshake header.
  for( Int32 count = 4; count < max; count++ )
    certBuf.appendU8( allBytes.getU8( count ));

  MsgID = Handshake::CertificateID;
  CertMesg certMesg;
  return certMesg.parseCertMsg( certBuf,
                                tlsMain );
  }

if( recordType ==
            Handshake::CertificateRequestID )
  {
  StIO::putS( "CertificateRequestID" );

  MsgID = Handshake::CertificateRequestID;
  return Results::Done;
  }

if( recordType ==
            Handshake::CertificateVerifyID )
  {
  StIO::putS( "CertificateVerifyID" );

  tlsMain.setCertVerifyMsg( allBytes );

  CertVerMesg certVerMesg;
  certVerMesg.parseCertVerMsg( allBytes,
                               tlsMain );

  MsgID = Handshake::CertificateVerifyID;
  return Results::Done;
  }

if( recordType == Handshake::FinishedID )
  {
  // StIO::putS( "FinishedID" );

  // It came from the server.
  tlsMain.setSrvWriteFinishedMsg( allBytes );

  FinishedMesg finishedMesg;
  finishedMesg.parseMsg( allBytes,
                         tlsMain );

  MsgID = Handshake::FinishedID;
  return Results::Done;
  }

if( recordType == Handshake::KeyUpdateID )
  {
  StIO::putS( "KeyUpdateID" );

  MsgID = Handshake::KeyUpdateID;
  return Results::Done;
  }

if( recordType == Handshake::MessageHashID )
  {
  StIO::putS( "MessageHashID" );

  MsgID = Handshake::MessageHashID;
  return Results::Done;
  }


// HelloVerifyRequestRESERVED

if( recordType ==
       Handshake::HelloRetryRequestRESERVED )
  {
  StIO::putS( "HelloRetryRequestRESERVED" );

  MsgID = Handshake::HelloRetryRequestRESERVED;
  return Results::Done;
  }

// ServerKeyExchangeRESERVED
// ServerHelloDoneRESERVED
// ClientKeyExchangeRESERVED
// CertificateUrlRESERVED
// CertificateStatusRESERVED
// SupplementalDataRESERVED

StIO::putS(
  "HandshakeCl.parseMessage unexpected type." );

return Alerts::UnexpectedMessage;
}



Uint32 HandshakeCl::processInBuf(
                     const CharBuf& inBuf,
                     TlsMain& tlsMain,
                     Uint8& MsgID,
                     EncryptTls& encryptTls )
{
StIO::putS( "HandshakeCl processInBuf." );

// StIO::printFStack();

const Int32 recvLast = inBuf.getLast();

// StIO::printF( "recvLast: " );
// StIO::printFD( recvLast );
// StIO::putLF();

for( Int32 count = 0; count < recvLast; count++ )
  circBufIn.addU8( inBuf.getU8( count ));

// If this gets called it means it has one
// complete outer record.  But there
// might be multiple handshake messages in
// one outer record.  Or in the case of
// certificates, there might be multiple
// outer records to get one full handshake record.
// There should not be any non-handshake
// messages interleaved with handshake messages.

const Int32 max = circBufIn.getSize();
for( Int32 count = 0; count < max; count++ )
  {
  if( circBufIn.isEmpty())
    break;

  Uint8 aByte = circBufIn.getU8();
  Uint32 accumResult = accumByte( aByte );

  if( accumResult == Results::Continue )
    continue;  // Keep adding more bytes.

  if( accumResult < Results::AlertTop )
    {
    allBytes.clear();
    StIO::putS(
           "Error in HandshakeCl accumByte." );
    return accumResult;
    }

  if( accumResult == Results::Done )
    {
    StIO::putLF();
    StIO::putS( "Collected a Handshake message." );
    Uint32 parseResult = parseMessage(
                                tlsMain,
                                MsgID,
                                encryptTls );

    // Clear it for a new message.
    allBytes.clear();
    return parseResult;
    }
  }

// circBufIn is empty here, but allBytes
// might have a partial record.
// Like a partial certificate list that was
// too big for one outer rec.

if( allBytes.getLast() > 0 )
  StIO::putS( "allBytes has a partial message." );

return Results::Continue;
}



void HandshakeCl::makeClHelloBuf(
                     CharBuf& outBuf,
                     TlsMain& tlsMain,
                     EncryptTls& encryptTls )
{
outBuf.clear();
outBuf.appendU8( Handshake::ClientHelloID );

// Place-holder bytes for length.
// Big endian.
outBuf.appendU8( 0 );
outBuf.appendU8( 0 );
outBuf.appendU8( 0 );

// Big endian.
//  lengthMsg >> 16 ));
//  lengthMsg >> 8 ));
//  lengthMsg ));

// Version 3.3 is legacy from TLS 1.2.
// It just stays at these old numbers in
// future versions.
outBuf.appendU8( 3 );
outBuf.appendU8( 3 );

CharBuf cHelloBuf;
clientHello.makeHelloBuf( cHelloBuf,
                          tlsMain,
                          encryptTls );

outBuf.appendCharBuf( cHelloBuf );

// Minus 4 because of the one byte for rec type
// and 3 bytes for length.
Int32 lengthMsg = outBuf.getLast() - 4;

// Big-endian:
outBuf.setU8( 1,  (lengthMsg >> 16) & 0xFF );
outBuf.setU8( 2,  (lengthMsg >> 8) & 0xFF );
outBuf.setU8( 3,  lengthMsg & 0xFF );
}
