// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


#pragma once


#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"

#include "../Network/ExtenList.h"
#include "../Network/TlsMain.h"
#include "../Network/EncryptTls.h"



class ClientHello
  {
  private:
  bool testForCopy = false;
  CharBuf msgBytes;
  ExtenList extenList;

  public:
  ClientHello( void );
  ClientHello( const ClientHello& in );
  ~ClientHello( void );
  Uint32 parseBuffer( const CharBuf& inBuf,
                      TlsMain& tlsmain,
                      EncryptTls& encryptTls );

  void makeHelloBuf( CharBuf& outBuf,
                     TlsMain& tlsMain,
                     EncryptTls& encryptTls );


  };
