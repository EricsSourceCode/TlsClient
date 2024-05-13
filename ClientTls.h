// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html



#pragma once



#include "../CppBase/BasicTypes.h"
#include "TlsMainCl.h"



class ClientTls
  {
  private:
  bool testForCopy = false;
  TlsMainCl tlsMainCl;

  public:
  ClientTls( void )
    {
    }



  ClientTls( const ClientTls &in )
    {
    if( in.testForCopy )
      return;

    throw "ClientTls copy constructor.";
    }


  ~ClientTls( void )
    {
    }

  bool startHandshake(
                   const CharBuf& urlDomain,
                   const CharBuf& port );

  bool startTestVecHandshake(
                     const CharBuf& urlDomain,
                     const CharBuf& port );

  Int32 processData( CircleBuf& appOutBuf,
                     CircleBuf& appInBuf );

  };
