// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html



// For information and guides see:
// https://ericssourcecode.github.io/


#include "TlsMainCl.h"
#include "../CppBase/StIO.h"



Int32 TlsMainCl::processOutgoing(
                         CircleBuf& appOutBuf )
{
CharBuf sendOutBuf;
copyOutBuf( sendOutBuf );
Int32 outLast = sendOutBuf.getLast();
Int32 howMany = 0;
if( outLast > 0 )
  {
  howMany = netClient.sendCharBuf( sendOutBuf );
  }

if( howMany < outLast )
  {
  StIO::putS(
          "TlsMainCl could not write all data." );
  // Then do what about this?
  // Use a CircleBuf to write it?
  return -1;
  }

if( encryptTls.getAppKeysSet())
  {
  CharBuf plainBuf;
  const Int32 last =
            tlsMain.getMaxFragLength() - 1024;

  for( Int32 count = 0; count < last; count++ )
    {
    if( appOutBuf.isEmpty())
      break;

    plainBuf.appendU8( appOutBuf.getU8());
    }

  CharBuf outerRecBuf;
  encryptTls.clWriteMakeOuterRec( plainBuf,
              outerRecBuf,
              TlsOuterRec::ApplicationData );

  outLast = outerRecBuf.getLast();
  if( outLast > 0 )
    {
    StIO::putS( "Sending app data." );
    // outerRecBuf.showHex();
    // plainBuf.showAscii();
    // StIO::putLF();

    howMany = netClient.sendCharBuf(
                            outerRecBuf );
    }

  if( howMany < outLast )
    {
    StIO::putS(
        "TlsMainCl could not write all data." );
    // Then do what about this?
    // Use a CircleBuf to write it?
    return -1;
    }

  }

return 1;
}


Int32 TlsMainCl::processIncoming(
                          CircleBuf& appInBuf )
{
CharBuf recvBuf;
if( netClient.isConnected())
  netClient.receiveCharBuf( recvBuf );

const Int32 recvLast = recvBuf.getLast();

// StIO::printF(
//     "TlsMainCl::processIncoming bytes: " );
// StIO::printFD( recvLast );
// StIO::putLF();

if( recvLast > 0 )
  {
  // It received some new data.
  for( Int32 count = 0; count < recvLast;
                                      count++ )
    circBufIn.addU8( recvBuf.getU8( count ));

  }

const Int32 max = circBufIn.getSize();
for( Int32 count = 0; count < max; count++ )
  {
  if( circBufIn.isEmpty())
    break;

  Uint8 aByte = circBufIn.getU8();
  Uint32 accumResult = tlsOuterRead.
                           accumByte( aByte );
  if( accumResult == Results::Continue )
    continue; // Get more bytes.

  if( accumResult < Results::AlertTop )
    {
    StIO::putS(
             "tlsOuterRead.accumByte error." );
    sendPlainAlert( accumResult & 0xFF );
    tlsOuterRead.clear();
    // Cause it to time out with read closed.
    return 0;
    }

  if( accumResult == Results::Done )
    {
    recordBytes.clear();
    tlsOuterRead.copyBytes( recordBytes );
    Int32 recBytesLast = recordBytes.getLast();
    // StIO::printF( "recordBytes last: " );
    // StIO::printFD( recBytesLast );
    // StIO::putLF();

    Uint8 recType = tlsOuterRead.getRecordType();
    tlsOuterRead.clear();

    if( recType == TlsOuterRec::Handshake )
      {
      return processHandshake( recordBytes );
      }

    if( recType == TlsOuterRec::ChangeCipherSpec )
      {
      StIO::putS( "Got a ChangeCipherSpec." );
      StIO::putS( "Ignoring ChangeCipherSpec." );
      // Don't do anything.  Just ignore it.
      return true;
      }

    if( recType == TlsOuterRec::Alert )
      {
      if( recBytesLast != 2 )
        throw "Alert recBytesLast is not right.";

      // An alert is the outer record alert
      // record type, then legacy version 3.3,
      // then length for 2 bytes, and it's
      // always a length of 2. Then the
      // level and then description.

      StIO::putS( "Got an Alert." );

      // Get the second byte:
      const Uint8 descript = recordBytes.
                                    getU8( 1 );
      Alerts::showAlert( descript );
      return -1; // Shut it down.
      }

    if( recType == TlsOuterRec::ApplicationData )
      {
      // StIO::putS( "Got ApplicationData." );

      // Int32 appBytesLast =
      //       recordBytes.getLast();
      // StIO::printF( "appBytes last: " );
      // StIO::printFD( appBytesLast );
      // StIO::putLF();

      // recordBytes is everything except
      // the 5 starting bytes.
      // The five bytes are:
      // 23, 3, 3, recordBytes.getLast()

      CharBuf plainBuf;
      encryptTls.srvWriteDecryptCharBuf(
                  recordBytes,
                  plainBuf );

      return processAppData( plainBuf,
                             appInBuf );
      }


    //  RFC 6520
    if( recType == TlsOuterRec::HeartBeat )
      {
      StIO::putS( "Got a HeartBeat." );
      return 1;
      }

    // It didn't find any matching type.
    sendPlainAlert( Alerts::UnexpectedMessage );
    return -1;
    }
  }

if( circBufIn.isEmpty())
  {
  // Do this after processing data in circBuf.
  if( !netClient.isConnected())
    return -1;

  }

return 1;
}



Int32 TlsMainCl::processHandshake(
                     const CharBuf& inBuf )
{
StIO::putS( "TlsMainCl.processHandshake()" );

CharBuf inBufOnce;
inBufOnce.copy( inBuf );

// Loop and get all messages.
for( Int32 count = 0; count < 100; count++ )
  {
  Uint8 msgID = 0;

  Uint32 hResult = handshakeCl.processInBuf(
                                inBufOnce,
                                tlsMain,
                                msgID,
                                encryptTls );

  // Clear it after the first one because
  // it has already put it in its own
  // circleBuf.

  inBufOnce.clear();

  if( hResult < Results::AlertTop )
    {
    StIO::putS( "Handshake processInbuf error." );
    sendPlainAlert( hResult & 0xFF );
    // Cause it to time out with read closed.
    return 0;
    }

  if( hResult == Results::Continue )
    return 1;

  // StIO::printF( "msgID: " );
  // StIO::printFUD( msgID );
  // StIO::putLF();

  // This isn't right.
  // NewSessionTicketID can be out of order.
  // This would be a more complex function
  // to check the order of these messages.
  // section-4.6.1
  // It is not part of the handshake.
  // It is ordinary app data.
  // At any time after
  // the server has received
  // the client Finished
  //  message, it MAY send a NewSessionTicket
  // message.

  // if( tlsMain.getLastHandshakeID() >= msgID )
    // {
    // StIO::putS(
    //    "Handshake message out of order." );
    // Which alert is this?
    // sendPlainAlert(
    //       Alerts::UnexpectedMessage );
    // return -1;
    // }

  // HelloRequestRESERVED = 0;

  if( msgID == Handshake::ClientHelloID )
    {
    StIO::putS(
           "Client got a ClientHello." );
    // sendPlainAlert(
    //        Alerts::UnexpectedMessage );
    return -1;
    }

  if( msgID == Handshake::ServerHelloID )
    {
    StIO::putS( "Got a ServerHello." );
    tlsMain.setLastHandshakeID(
                   Handshake::ServerHelloID );

    Integer sharedS;
    encryptTls.setDiffHelmOnClient(
                          tlsMain, sharedS );

    encryptTls.setHandshakeKeys( tlsMain,
                                 sharedS );
    return 1;
    }

  // HelloVerifyRequestRESERVED = 3;

  if( msgID == Handshake::NewSessionTicketID )
    {
    StIO::putS( "Got a NewSessionTicketID." );
    tlsMain.setLastHandshakeID(
             Handshake::NewSessionTicketID );
    continue;
    }

  if( msgID == Handshake::EndOfEarlyDataID )
    {
    StIO::putS( "Got a EndOfEarlyDataID." );
    tlsMain.setLastHandshakeID(
             Handshake::EndOfEarlyDataID );
    continue;
    }

  if( msgID ==
         Handshake::HelloRetryRequestRESERVED )
    {
    StIO::putS(
          "Got a HelloRetryRequestRESERVED." );
    tlsMain.setLastHandshakeID(
         Handshake::HelloRetryRequestRESERVED );
    continue;
    }

  if( msgID == Handshake::EncryptedExtensionsID )
    {
    StIO::putS( "Got an EncryptedExtensionsID." );
    tlsMain.setLastHandshakeID(
             Handshake::EncryptedExtensionsID );

    continue;
    }

  if( msgID == Handshake::CertificateID )
    {
    StIO::putS(
         "Got a CertificateID." );
    tlsMain.setLastHandshakeID(
             Handshake::CertificateID );
    continue;
    }

  if( msgID == Handshake::CertificateRequestID )
    {
    StIO::putS( "Got a CertificateRequestID." );
    tlsMain.setLastHandshakeID(
             Handshake::CertificateRequestID );
    continue;
    }

  if( msgID == Handshake::CertificateVerifyID )
    {
    StIO::putS( "Got a CertificateVerifyID." );
    tlsMain.setLastHandshakeID(
             Handshake::CertificateVerifyID );
    continue;
    }

  if( msgID == Handshake::FinishedID )
    {
    StIO::putS( "Got a FinishedID." );
    tlsMain.setLastHandshakeID(
             Handshake::FinishedID );

    // FinishedMesg finished;
    // finished.

    // Just received the Server's Finished
    // Message, so send the client's
    // Finished message.

    CharBuf finished;
    encryptTls.makeClFinishedMsg( tlsMain,
                                  finished );

    CharBuf outerRecBuf;
    encryptTls.clWriteMakeOuterRec( finished,
                      outerRecBuf,
                      TlsOuterRec::Handshake );

    outgoingBuf.appendCharBuf( outerRecBuf );

    // if( !sendTestVecFinished())
      // return -1;

    encryptTls.setAppDataKeys( tlsMain );
    continue;
    }

  if( msgID == Handshake::KeyUpdateID )
    {
    StIO::putS( "Got a KeyUpdateID." );
    tlsMain.setLastHandshakeID(
             Handshake::KeyUpdateID );
    continue;
    }

  if( msgID == Handshake::MessageHashID )
    {
    StIO::putS( "Got a MessageHashID." );
    tlsMain.setLastHandshakeID(
             Handshake::MessageHashID );
    continue;
    }

  throw "Handshake message unknown.";
  }

// If someone put over 100 handshake messages
// in to one outer record.

StIO::putS( "It should never loop 100 times." );
return -1;
}



Int32 TlsMainCl::processAppData(
                     const CharBuf& plainText,
                     CircleBuf& appInBuf )
{
// StIO::putS( "App data plainText:" );
// plainText.showHex();

CharBuf messages;
messages.copy( plainText );

Int32 paddingLast = 0;
const Int32 max = plainText.getLast();

if( max == 0 )
  {
  StIO::putS(
       "processAppData messages was empty." );
  return 0;
  }

for( Int32 count = max - 1; count >= 0; count-- )
  {
  Uint8 aByte = plainText.getU8( count );
  if( aByte != 0 )
    {
    paddingLast = count + 1;
    break;
    }
  }

if( paddingLast == 0 )
  {
  StIO::putS(
     "processAppData Message was all padding." );
  return 0;
  }

messages.truncateLast( paddingLast );

// The messageType is an OuterRec type.
Int32 messageType = messages.getU8(
                           paddingLast - 1 );

messages.truncateLast( paddingLast - 1 );


// ChangeCipherSpec = 20;
// Alert = 21;
// Handshake = 22;
// ApplicationData = 23;
// HeartBeat = 24;

if( messageType == TlsOuterRec::Handshake )
  {
  return processHandshake( messages );
  }

if( messageType == TlsOuterRec::ChangeCipherSpec )
  {
  StIO::putS(
           "messageType is ChangeCipherSpec." );

  return 0;
  }

if( messageType == TlsOuterRec::Alert )
  {
  StIO::putS( "messageType is Alert." );
  return 1;
  }

if( messageType == TlsOuterRec::ApplicationData )
  {
  // StIO::putS( "App messages:" );
  // messages.showHex();
  // messages.showAscii();

  appInBuf.addCharBuf( messages );

  // StIO::printF( "appInBuf size:: " );
  // Int32 appLast = appInBuf.getHowMany();
  // StIO::printFD( appLast );
  // StIO::putLF();

  return 1;
  }

if( messageType == TlsOuterRec::HeartBeat )
  {
  StIO::putS( "messageType is HeartBeat." );
  return 1;
  }

throw "Application messageType is unknown.";
// return -1;
}



void TlsMainCl::sendPlainAlert(
                           const Uint8 descript )
{
// An alert sent in Plain Text.

// ======
// This has to be sent as an encrypted
// record sometimes.

// Pretend the parameter is being used.
if( descript == 0xFF ) // Doesn't happen.
  StIO::printF( "Parameter is being used." );
else
  throw "Send plain alert needs work.";


/*
StIO::printF( "Sending Alert: " );
StIO::printFUD( descript );
StIO::putLF();

const Uint8 level = Alerts::getMatchingLevel(
                                     descript );

// Alerts are in RFC 8446, Section 6.

outgoingBuf.appendU8( TlsOuterRec::Alert );

// Legacy version:
outgoingBuf.appendU8( 3 );
outgoingBuf.appendU8( 3 );

// Length:
outgoingBuf.appendU8( 0 );
outgoingBuf.appendU8( 2 );

outgoingBuf.appendU8( level );
outgoingBuf.appendU8( descript );
*/
}


void TlsMainCl::copyOutBuf( CharBuf& sendOutBuf )
{
sendOutBuf.copy( outgoingBuf );
outgoingBuf.clear();
}




bool TlsMainCl::sendTestVecFinished( void )
{
StIO::putS( "Sending test vec finished." );

// This includes the handshake header.
const char* vecFinishedMsgString =
          "14 00 00 20 a8 ec 43 6d 67 76 34"
          "ae 52 5a c1 fc eb e1 1a 03 9e c1"
          "76 94 fa c6 e9 85 27 b6 42 f2 ed"
          "d5 ce 61";

CharBuf testVecMsgBuf( vecFinishedMsgString );

CharBuf finMsgBuf;
finMsgBuf.setFromHexTo256( testVecMsgBuf );

StIO::putS( "finMsgBuf:" );
finMsgBuf.showHex();
StIO::putLF();

tlsMain.setClWriteFinishedMsg( finMsgBuf );

const char* vecFinishedString =
      "17 03 03 00 35 75 ec 4d c2 38 cc e6"
      "0b 29 80 44 a7 1e 21 9c 56 cc 77 b0"
      "51 7f e9 b9 3c 7a 4b fc 44 d8 7f 38"
      "f8 03 38 ac 98 fc 46 de b3 84 bd 1c"
      "ae ac ab 68 67 d7 26 c4 05 46";

CharBuf testVecBuf( vecFinishedString );

CharBuf finRecBuf;
finRecBuf.setFromHexTo256( testVecBuf );

StIO::putS( "finRecBuf:" );
finRecBuf.showHex();
StIO::putLF();


outgoingBuf.appendCharBuf( finRecBuf );

return true;
}




bool TlsMainCl::startTestVecHandshake(
                        const CharBuf& urlDomain,
                        const CharBuf& port )
{
StIO::putS( "Connecting to server." );

if( !netClient.connect( urlDomain, port ))
  return false;

Integer k;
Integer pubKey;

// Test key values from RFC 8448.
// x25519 key pair:

// Little endian:
const char* privKeyString =
      "49 af 42 ba 7f 79 94 85"
      "2d 71 3e f2 78 4b cb ca"
      "a7 91 1d e2 6a dc 56 42"
      "cb 63 45 40 e7 ea 50 05";

const char* pubKeyString =
      "99 38 1d e5 60 e4 bd 43"
      "d2 3d 8e 43 5a 7d ba fe"
      "b3 c0 6e 51 c1 3c ae 4d"
      "54 13 69 1e 52 9a af 2c";

StIO::putS( "Private key:" );
CharBuf privKeyStrBuf( privKeyString );
CharBuf privKeyBuf;
privKeyBuf.setFromHexTo256( privKeyStrBuf );
privKeyBuf.showHex();
ByteArray cArray;
privKeyBuf.copyToCharArray( cArray );

// This clampK has to be done.
tlsMain.mCurve.clampK( cArray );

tlsMain.mCurve.cArrayToInt( cArray, k );

StIO::putS( "Public key:" );
CharBuf pubKeyStrBuf( pubKeyString );
CharBuf pubKeyBuf;
pubKeyBuf.setFromHexTo256( pubKeyStrBuf );
pubKeyBuf.showHex();
pubKeyBuf.copyToCharArray( cArray );
tlsMain.mCurve.cArrayToInt( cArray, pubKey );

// Raise 9 to k and see if I get pubkey.

Integer U;
U.setFromLong48( 9 );
Integer pubKeyTest;
tlsMain.mCurve.montLadder1(
                     pubKeyTest, U, k,
                     tlsMain.intMath,
                     tlsMain.mod );

tlsMain.mCurve.uCoordTo32Bytes( pubKeyTest,
                        cArray, tlsMain.mod,
                        tlsMain.intMath );

StIO::putS( "pubKeyTest:" );
CharBuf testBuf;
testBuf.appendCharArray( cArray, 32 );
testBuf.showHex();

if( !pubKey.isEqual( pubKeyTest ))
  throw
    "startTestVecHandshake Test keys not right.";

StIO::putS( "Got the keys right." );

// This is the clamped value.
encryptTls.setClientPrivKey( k );
encryptTls.setClientPubKey( pubKey );


// tlsMain.setServerName( urlDomain );

// This test message has the server name
// extension with the name "server".
tlsMain.setServerName( "server" );

// From RFC 8448:

// The client Hello message, used to
// derive the keys.

const char* clHelloString =
        "01 00 00 c0 03 03 cb"
        "34 ec b1 e7 81 63 ba 1c 38 c6 da"
        "cb 19 6a 6d ff a2 1a 8d 99 12"
        "ec 18 a2 ef 62 83 02 4d ec e7 00"
        "00 06 13 01 13 03 13 02 01 00"
        "00 91 00 00 00 0b 00 09 00 00 06"
        "73 65 72 76 65 72 ff 01 00 01"
        "00 00 0a 00 14 00 12 00 1d 00 17"
        "00 18 00 19 01 00 01 01 01 02"
        "01 03 01 04 00 23 00 00 00 33 00"
        "26 00 24 00 1d 00 20 99 38 1d"
        "e5 60 e4 bd 43 d2 3d 8e 43 5a 7d"
        "ba fe b3 c0 6e 51 c1 3c ae 4d"
        "54 13 69 1e 52 9a af 2c 00 2b 00"
        "03 02 03 04 00 0d 00 20 00 1e"
        "04 03 05 03 06 03 02 03 08 04 08"
        "05 08 06 04 01 05 01 06 01 02"
        "01 04 02 05 02 06 02 02 02 00 2d"
        "00 02 01 01 00 1c 00 02 40 01";

CharBuf clHelloBuf( clHelloString );

CharBuf clRecBuf;
clRecBuf.setFromHexTo256( clHelloBuf );

StIO::putS( "clRecBuf:" );
clRecBuf.showHex();

tlsMain.setClientHelloMsg( clRecBuf );


// The client Hello message.  This is the
// whole thing with the outer record.

const char* clHelloRecString =
        "16 03 01 00 c4 01 00 00 c0 03 03 cb"
        "34 ec b1 e7 81 63 ba 1c 38 c6 da"
        "cb 19 6a 6d ff a2 1a 8d 99 12"
        "ec 18 a2 ef 62 83 02 4d ec e7 00"
        "00 06 13 01 13 03 13 02 01 00"
        "00 91 00 00 00 0b 00 09 00 00 06"
        "73 65 72 76 65 72 ff 01 00 01"
        "00 00 0a 00 14 00 12 00 1d 00 17"
        "00 18 00 19 01 00 01 01 01 02"
        "01 03 01 04 00 23 00 00 00 33 00"
        "26 00 24 00 1d 00 20 99 38 1d"
        "e5 60 e4 bd 43 d2 3d 8e 43 5a 7d"
        "ba fe b3 c0 6e 51 c1 3c ae 4d"
        "54 13 69 1e 52 9a af 2c 00 2b 00"
        "03 02 03 04 00 0d 00 20 00 1e"
        "04 03 05 03 06 03 02 03 08 04 08"
        "05 08 06 04 01 05 01 06 01 02"
        "01 04 02 05 02 06 02 02 02 00 2d"
        "00 02 01 01 00 1c 00 02 40 01";

CharBuf clHelloRecBuf( clHelloRecString );

CharBuf recordBuf;
recordBuf.setFromHexTo256( clHelloRecBuf );

StIO::putS( "recordBuf:" );

recordBuf.showHex();

StIO::putS( "End of recordBuf." );

Int32 sentBytes = netClient.sendCharBuf(
                                 recordBuf );

StIO::printF( "Sent bytes: " );
StIO::printFD( sentBytes );
StIO::putLF();

return true;
}



bool TlsMainCl::startHandshake(
                      const CharBuf& urlDomain,
                      const CharBuf& port )
{
StIO::putS( "Connecting to server." );

if( !netClient.connect( urlDomain, port ))
  return false;

tlsMain.setServerName( urlDomain );

CharBuf cHelloBuf;

handshakeCl.makeClHelloBuf( cHelloBuf,
                            tlsMain,
                            encryptTls );

tlsMain.setClientHelloMsg( cHelloBuf );

Int32 cHelloBufLen = cHelloBuf.getLast();
StIO::printF( "cHelloBufLen: " );
StIO::printFD( cHelloBufLen );
StIO::putLF();

CharBuf recBuf;
TlsOuterRec outerRec;

Int32 howMany = outerRec.makeHandshakeRec(
                   cHelloBuf, recBuf, tlsMain );

// StIO::printF( "howMany: " );
// StIO::printFD( howMany );
// StIO::putLF();

if( (cHelloBufLen + 5) != howMany )
  throw "Fix cHelloBuf not all sent.";

Int32 sentBytes = netClient.sendCharBuf( recBuf );

StIO::printF( "Sent bytes: " );
StIO::printFD( sentBytes );
StIO::putLF();

// Fix this up.
if( sentBytes != howMany )
  throw "Fix sentBytes in startHandshake.";

  // return -1;

return howMany;
}
