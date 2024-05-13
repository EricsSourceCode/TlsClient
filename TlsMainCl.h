// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


// For information and guides see:
// https://ericssourcecode.github.io/




#pragma once


#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"
#include "../CppBase/CircleBuf.h"
#include "../Network/TlsMain.h"
#include "../Network/Alerts.h"
#include "../Network/Handshake.h"
#include "HandshakeCl.h"
#include "../Network/Results.h"
#include "../Network/TlsOuterRec.h"
#include "../Network/EncryptTls.h"
#include "../Network/NetClient.h"



class TlsMainCl
  {
  private:
  bool testForCopy = false;
  TlsMain tlsMain;
  NetClient netClient;
  CircleBuf circBufIn;
  CharBuf recordBytes;
  CharBuf outgoingBuf;
  TlsOuterRec tlsOuterRead;
  HandshakeCl handshakeCl;
  EncryptTls encryptTls;

  public:
  TlsMainCl( void )
    {
    // It might receive big files with this.
    circBufIn.setSize(
         1024 * 1024 );

    }


  TlsMainCl( const TlsMainCl &in )
    {
    if( in.testForCopy )
      return;

    throw "TlsMainCl copy constructor.";
    }

  ~TlsMainCl( void )
    {
    }

  void sendPlainAlert( const Uint8 descript );

  Int32 processIncoming( CircleBuf& appInBuf );

  Int32 processOutgoing(
                     CircleBuf& appOutBuf );

  void copyOutBuf( CharBuf& sendOutBuf );

  Int32 processAppData(
                    const CharBuf& plainText,
                    CircleBuf& appInBuf );

  Int32 processHandshake(
                     const CharBuf& inBuf );

  bool sendTestVecFinished( void );

  bool startTestVecHandshake(
                     const CharBuf& urlDomain,
                     const CharBuf& port );

  bool startHandshake( const CharBuf& urlDomain,
                       const CharBuf& port );


  };
