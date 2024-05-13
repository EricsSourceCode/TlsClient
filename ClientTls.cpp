// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


#include "ClientTls.h"
#include "../Network/TlsOuterRec.h"
#include "../Network/Handshake.h"
#include "../CppBase/Casting.h"
#include "../CppBase/CharBuf.h"




bool ClientTls::startTestVecHandshake(
                        const CharBuf& urlDomain,
                        const CharBuf& port )
{
return tlsMainCl.startTestVecHandshake(
                             urlDomain, port );
}



bool ClientTls::startHandshake(
                        const CharBuf& urlDomain,
                        const CharBuf& port )
{
return tlsMainCl.startHandshake(
                          urlDomain, port );
}



Int32 ClientTls::processData(
                       CircleBuf& appOutBuf,
                       CircleBuf& appInBuf )
{
try
{
Int32 status = tlsMainCl.processIncoming(
                                   appInBuf );

if( status < 0 )
  return -1;

Int32 status2 = tlsMainCl.processOutgoing(
                                 appOutBuf );

if( status == 0 )
  {
  // Let it time out and close.
  return 0;
  }

return status2;

}
catch( const char* in )
  {
  StIO::putS(
         "Exception in ClientTls.processData:" );
  StIO::putS( in );
  return -1;
  }
catch( ... )
  {
  StIO::putS(
          "Exception in ClientTls.processData" );
  return -1;
  }
}
