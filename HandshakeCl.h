// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


#pragma once



#include "../CppBase/BasicTypes.h"
#include "../Network/Handshake.h"
#include "../CppBase/CharBuf.h"
#include "../CppBase/CircleBuf.h"
#include "../CppInt/IntegerMath.h"
#include "../CppInt/Mod.h"
#include "../CryptoBase/MCurve.h"
#include "ClientHello.h"
#include "../TlsServer/ServerHello.h"
#include "../Network/TlsMain.h"



class HandshakeCl
  {
  private:
  bool testForCopy = false;
  CharBuf allBytes;
  Uint8 recordType = 0;
  Int32 recLength = 0;
  CircleBuf circBufIn;

  Uint32 accumByte( Uint8 toAdd );

  Uint32 parseMessage( TlsMain& tlsMain,
                       Uint8& MsgID,
                       EncryptTls& encryptTls );

  public:
  ClientHello clientHello;
  ServerHello serverHello;

  HandshakeCl( void );
  HandshakeCl( const HandshakeCl& in );
  ~HandshakeCl( void );

  Uint32 processInBuf( const CharBuf& hsBuf,
                       TlsMain& tlsMain,
                       Uint8& MsgID,
                       EncryptTls& encryptTls );

  void makeClHelloBuf( CharBuf& outBuf,
                    TlsMain& tlsMain,
                    EncryptTls& encryptTls );

  };
