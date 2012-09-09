{- |
Module      : System.Linux.SELinux
Copyright   : Luite Stegeman
Licence     : BSD3

Maintainer  : stegeman@gmail.com
Stability   : provisional
Portability : portable

Haskell bindings for the SELinux API.
-}

{-#LANGUAGE ForeignFunctionInterface #-}

{-
  incomplete bindings, feel free to extend
-}

module System.Linux.SELinux (
  SecurityContext,
  EnforceMode(..),
  isSELinuxEnabled,
  isSELinuxMLSEnabled,
  getEnforceMode,
  getEnforce,
  getCon, getConRaw, setCon, setConRaw,
  getPidCon, getPidConRaw,
  getPrevCon, getPrevConRaw,
  getExecCon, getExecConRaw, setExecCon, setExecConRaw,
  getFsCreateCon, getFsCreateConRaw, setFsCreateCon, setFsCreateConRaw,
  getKeyCreateCon, getKeyCreateConRaw, setKeyCreateCon, setKeyCreateConRaw,
  getSockCreateCon, getSockCreateConRaw, setSockCreateCon, setSockCreateConRaw,
  getFileCon, getFileConRaw,
  lgetFileCon, lgetFileConRaw,
  fgetFileCon, fgetFileConRaw,
  setFileCon, setFileConRaw,
  lsetFileCon, lsetFileConRaw,
  fsetFileCon, fsetFileConRaw,
  getPeerCon, getPeerConRaw,
  getConfigPolicyRoot, getConfigBinaryPolicyPath,
  getConfigFailsafeContextPath, getConfigRemovableContextPath,
  getConfigDefaultContextPath, getConfigUserContextsPath,
  getConfigFileContextPath, getConfigFileContextHomedirPath,
  getConfigFileContextLocalPath, getConfigFileContextSubsPath,
  getConfigHomedirContextPath, getConfigMediaContextPath,
  getConfigVirtualDomainContextPath, getConfigVirtualImageContextPath,
  getConfigXContextPath, getConfigSepgsqlContextPath,
  getConfigContextsPath, getConfigSecurettyTypesPath,
  getConfigBooleansPath, getConfigCustomizableTypesPath,
  getConfigUsersPath, getConfigUsersconfPath,
  getConfigTranslationsPath, getConfigColorsPath,
  getConfigNetfilterContextPath, getConfigPath 
 ) where

import Control.Monad
import Foreign.C.Types (CInt(..))
import Foreign.C.String (CString, withCString, peekCString)
import Foreign.C.Error (throwErrnoIfMinus1, throwErrnoIfMinus1_, throwErrno)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, nullPtr)
import Foreign.Storable (peek)
import System.Posix.Types (CPid(..))


type SecurityContext = String

data EnforceMode = Enforcing 
                 | Permissive 
                 | Disabled deriving (Show, Ord, Eq)

isSELinuxEnabled :: IO Bool
isSELinuxEnabled = fmap i2b $ throwErrnoIfMinus1 "isSELinuxEnabled" c_is_selinux_enabled

isSELinuxMLSEnabled :: IO Bool
isSELinuxMLSEnabled = fmap i2b $ throwErrnoIfMinus1 "isSELinuxMLSEnabled" c_is_selinux_mls_enabled

getEnforceMode :: IO EnforceMode
getEnforceMode = alloca $ \ptr -> do
  r <- c_selinux_getenforcemode ptr
  if r == -1 
    then throwErrno "getEnforceMode"
    else fmap convertEnforceMode (peek ptr)
  where
    convertEnforceMode 1 = Enforcing
    convertEnforceMode 0 = Permissive
    convertEnforceMode _ = Disabled
    
getEnforce :: IO Bool
getEnforce = fmap i2b $ throwErrnoIfMinus1 "getEnforce" c_security_getenforce

getCon              = queryCon "getCon" c_getcon
getConRaw           = queryCon "getConRaw" c_getcon_raw
setCon              = withCon  "setCon" c_setcon
setConRaw           = withCon  "setConRaw" c_setcon_raw
getPidCon pid       = queryCon "getPidCon" (c_getpidcon pid)
getPidConRaw pid    = queryCon "getPidConRaw" (c_getpidcon_raw pid)
getPrevCon          = queryCon "getPrevCon" c_getprevcon
getPrevConRaw       = queryCon "getPrevConRaw" c_getprevcon_raw

getExecCon          = queryConMaybe "getExecCon" c_getexeccon
getExecConRaw       = queryConMaybe "getExecConRaw" c_getexeccon_raw
setExecCon          = withConMaybe "setExecCon" c_setexeccon
setExecConRaw       = withConMaybe "setExecConRaw" c_setexeccon_raw

getFsCreateCon      = queryConMaybe "getFsCreateCon" c_getfscreatecon
getFsCreateConRaw   = queryConMaybe "getFsCreateConRaw" c_getfscreatecon_raw
setFsCreateCon      = withConMaybe "setFsCreateCon" c_setfscreatecon
setFsCreateConRaw   = withConMaybe "setFsCreateConRaw" c_setfscreatecon_raw

getKeyCreateCon     = queryConMaybe "getKeyCreateCon" c_getkeycreatecon
getKeyCreateConRaw  = queryConMaybe "getKeyCreateConRaw" c_getkeycreatecon_raw
setKeyCreateCon     = withConMaybe "setKeyCreateCon" c_setkeycreatecon
setKeyCreateConRaw  = withConMaybe "setKeyCreateConRaw" c_setkeycreatecon_raw

getSockCreateCon    = queryConMaybe "getSockCreateCon" c_getsockcreatecon
getSockCreateConRaw = queryConMaybe "getSockCreateConRaw" c_getsockcreatecon_raw
setSockCreateCon    = withConMaybe "setSockCreateCon" c_setsockcreatecon
setSockCreateConRaw = withConMaybe "setSockCreateConRaw" c_setsockcreatecon_raw

getFileCon          = queryPathCon "getFileCon" c_getfilecon
getFileConRaw       = queryPathCon "getFileConRaw" c_getfilecon_raw
lgetFileCon         = queryPathCon "lgetFileCon" c_lgetfilecon
lgetFileConRaw      = queryPathCon "lgetFileConRw" c_lgetfilecon_raw
fgetFileCon fd      = queryCon "fgetFileCon" (c_fgetfilecon fd)
fgetFileConRaw fd   = queryCon "fgetFileConRaw" (c_fgetfilecon_raw fd)

setFileCon          = withPathCon "setFileCon" c_setfilecon
setFileConRaw       = withPathCon "setFileConRaw" c_setfilecon_raw
lsetFileCon         = withPathCon "lsetFileCon" c_lsetfilecon
lsetFileConRaw      = withPathCon "lsetfileConRaw" c_lsetfilecon_raw
fsetFileCon fd      = withCon "fsetFileCon" (c_fsetfilecon fd)
fsetFileConRaw fd   = withCon "fsetFileConRaw" (c_fsetfilecon_raw fd)

getPeerCon fd       = queryCon "getPeerCon" (c_getpeercon fd)
getPeerConRaw fd    = queryCon "getPeerConRaw" (c_getpeercon_raw fd)

getConfigPolicyRoot               = queryConfig c_selinux_policy_root
getConfigBinaryPolicyPath         = queryConfig c_selinux_binary_policy_path
getConfigFailsafeContextPath      = queryConfig c_selinux_failsafe_context_path
getConfigRemovableContextPath     = queryConfig c_selinux_removable_context_path
getConfigDefaultContextPath       = queryConfig c_selinux_default_context_path
getConfigUserContextsPath         = queryConfig c_selinux_user_contexts_path
getConfigFileContextPath          = queryConfig c_selinux_file_context_path
getConfigFileContextHomedirPath   = queryConfig c_selinux_file_context_homedir_path
getConfigFileContextLocalPath     = queryConfig c_selinux_file_context_local_path
getConfigFileContextSubsPath      = queryConfig c_selinux_file_context_subs_path
getConfigHomedirContextPath       = queryConfig c_selinux_homedir_context_path
getConfigMediaContextPath         = queryConfig c_selinux_media_context_path
getConfigVirtualDomainContextPath = queryConfig c_selinux_virtual_domain_context_path
getConfigVirtualImageContextPath  = queryConfig c_selinux_virtual_image_context_path
getConfigXContextPath             = queryConfig c_selinux_x_context_path
getConfigSepgsqlContextPath       = queryConfig c_selinux_sepgsql_context_path
getConfigContextsPath             = queryConfig c_selinux_contexts_path
getConfigSecurettyTypesPath       = queryConfig c_selinux_securetty_types_path
getConfigBooleansPath             = queryConfig c_selinux_booleans_path
getConfigCustomizableTypesPath    = queryConfig c_selinux_customizable_types_path
getConfigUsersPath                = queryConfig c_selinux_users_path
getConfigUsersconfPath            = queryConfig c_selinux_usersconf_path
getConfigTranslationsPath         = queryConfig c_selinux_translations_path
getConfigColorsPath               = queryConfig c_selinux_colors_path
getConfigNetfilterContextPath     = queryConfig c_selinux_netfilter_context_path
getConfigPath                     = queryConfig c_selinux_path

---------------------------------------------------------------------------

i2b :: CInt -> Bool
i2b 0 = False
i2b _ = True

withCon :: String -> (CSecurityContext -> IO CInt) -> SecurityContext -> IO ()
withCon e f c = withCString c $ \ctx -> throwErrnoIfMinus1_ e (f ctx)
  
withConMaybe :: String -> (CSecurityContext -> IO CInt) -> Maybe SecurityContext -> IO ()
withConMaybe e f (Just c) = withCon e f c
withConMaybe e f Nothing  = throwErrnoIfMinus1_ e (f nullPtr)
  
withPathCon :: String -> (CString -> CSecurityContext -> IO CInt) -> FilePath -> SecurityContext -> IO ()
withPathCon e f p c = withCString p $ \cp -> withCon e (f cp) c

queryPathCon :: String -> (CString -> Ptr CSecurityContext -> IO CInt) -> FilePath -> IO SecurityContext
queryPathCon e f p = withCString p $ \p' -> queryCon e (f p')

queryCon :: String -> (Ptr CSecurityContext -> IO CInt) -> IO SecurityContext
queryCon e f = alloca $ \ptr -> do
  r <- f ptr
  if r == -1
    then throwErrno e
    else peek ptr >>= \ptr' -> peekCString ptr' >>= \str -> c_freecon ptr' >> return str
                                              
queryConMaybe :: String -> (Ptr CSecurityContext -> IO CInt) -> IO (Maybe SecurityContext)
queryConMaybe e f = alloca $ \ptr -> do
  r <- f ptr
  if r == -1
    then throwErrno e
    else peek ptr >>= \ptr' -> 
      if ptr' == nullPtr
        then return Nothing 
        else peekCString ptr' >>= \str -> c_freecon ptr' >> return (Just str)
                                          
-- |A helper function for reading values from the selinux config file
queryConfig :: IO CString -> IO String
queryConfig f = f >>= peekCString >>= return


type CSecurityContext = CString
foreign import ccall unsafe "selinux/selinux.h is_selinux_enabled"     c_is_selinux_enabled     :: IO CInt
foreign import ccall unsafe "selinux/selinux.h is_selinux_mls_enabled" c_is_selinux_mls_enabled :: IO CInt
foreign import ccall unsafe "selinux/selinux.h selinux_getenforcemode" c_selinux_getenforcemode :: Ptr CInt -> IO CInt
foreign import ccall unsafe "selinux/selinux.h security_getenforce"    c_security_getenforce    :: IO CInt
foreign import ccall unsafe "selinux/selinux.h freecon"                c_freecon                :: CSecurityContext -> IO ()

foreign import ccall unsafe "selinux/selinux.h getcon"                 c_getcon                 :: Ptr CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h getcon_raw"             c_getcon_raw             :: Ptr CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h setcon"                 c_setcon                 :: CSecurityContext     -> IO CInt
foreign import ccall unsafe "selinux/selinux.h setcon_raw"             c_setcon_raw             :: CSecurityContext     -> IO CInt
foreign import ccall unsafe "selinux/selinux.h getpidcon"              c_getpidcon              :: CPid -> Ptr CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h getpidcon_raw"          c_getpidcon_raw          :: CPid -> Ptr CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h getprevcon"             c_getprevcon             :: Ptr CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h getprevcon_raw"         c_getprevcon_raw         :: Ptr CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h getexeccon"             c_getexeccon             :: Ptr CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h getexeccon_raw"         c_getexeccon_raw         :: Ptr CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h setexeccon"             c_setexeccon             :: CSecurityContext     -> IO CInt
foreign import ccall unsafe "selinux/selinux.h setexeccon_raw"         c_setexeccon_raw         :: CSecurityContext     -> IO CInt
foreign import ccall unsafe "selinux/selinux.h getfscreatecon"         c_getfscreatecon         :: Ptr CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h getfscreatecon_raw"     c_getfscreatecon_raw     :: Ptr CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h setfscreatecon"         c_setfscreatecon         :: CSecurityContext     -> IO CInt
foreign import ccall unsafe "selinux/selinux.h setfscreatecon_raw"     c_setfscreatecon_raw     :: CSecurityContext     -> IO CInt
foreign import ccall unsafe "selinux/selinux.h getkeycreatecon"        c_getkeycreatecon        :: Ptr CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h getkeycreatecon_raw"    c_getkeycreatecon_raw    :: Ptr CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h setkeycreatecon"        c_setkeycreatecon        :: CSecurityContext     -> IO CInt
foreign import ccall unsafe "selinux/selinux.h setkeycreatecon_raw"    c_setkeycreatecon_raw    :: CSecurityContext     -> IO CInt
foreign import ccall unsafe "selinux/selinux.h getsockcreatecon"       c_getsockcreatecon       :: Ptr CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h getsockcreatecon_raw"   c_getsockcreatecon_raw   :: Ptr CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h setsockcreatecon"       c_setsockcreatecon       :: CSecurityContext     -> IO CInt
foreign import ccall unsafe "selinux/selinux.h setsockcreatecon_raw"   c_setsockcreatecon_raw   :: CSecurityContext     -> IO CInt

foreign import ccall unsafe "selinux/selinux.h getfilecon"             c_getfilecon             :: CString -> Ptr CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h getfilecon_raw"         c_getfilecon_raw         :: CString -> Ptr CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h lgetfilecon"            c_lgetfilecon            :: CString -> Ptr CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h lgetfilecon_raw"        c_lgetfilecon_raw        :: CString -> Ptr CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h fgetfilecon"            c_fgetfilecon            :: CInt -> Ptr CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h fgetfilecon_raw"        c_fgetfilecon_raw        :: CInt -> Ptr CSecurityContext -> IO CInt

foreign import ccall unsafe "selinux/selinux.h setfilecon"             c_setfilecon             :: CString -> CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h setfilecon_raw"         c_setfilecon_raw         :: CString -> CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h lsetfilecon"            c_lsetfilecon            :: CString -> CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h lsetfilecon_raw"        c_lsetfilecon_raw        :: CString -> CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h fsetfilecon"            c_fsetfilecon            :: CInt -> CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h fsetfilecon_raw"        c_fsetfilecon_raw        :: CInt -> CSecurityContext -> IO CInt

foreign import ccall unsafe "selinux/selinux.h getpeercon"             c_getpeercon             :: CInt -> Ptr CSecurityContext -> IO CInt
foreign import ccall unsafe "selinux/selinux.h getpeercon_raw"         c_getpeercon_raw         :: CInt -> Ptr CSecurityContext -> IO CInt

foreign import ccall unsafe "selinux/selinux.h selinux_policy_root"    c_selinux_policy_root    :: IO CString

-- These functions return the paths to specific files under the  
-- policy root directory.
foreign import ccall unsafe "selinux/selinux.h selinux_binary_policy_path"          c_selinux_binary_policy_path          :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_failsafe_context_path"       c_selinux_failsafe_context_path       :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_removable_context_path"      c_selinux_removable_context_path      :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_default_context_path"        c_selinux_default_context_path        :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_user_contexts_path"          c_selinux_user_contexts_path          :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_file_context_path"           c_selinux_file_context_path           :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_file_context_homedir_path"   c_selinux_file_context_homedir_path   :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_file_context_local_path"     c_selinux_file_context_local_path     :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_file_context_subs_path"      c_selinux_file_context_subs_path      :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_homedir_context_path"        c_selinux_homedir_context_path        :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_media_context_path"          c_selinux_media_context_path          :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_virtual_domain_context_path" c_selinux_virtual_domain_context_path :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_virtual_image_context_path"  c_selinux_virtual_image_context_path  :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_x_context_path"              c_selinux_x_context_path              :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_sepgsql_context_path"        c_selinux_sepgsql_context_path        :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_contexts_path"               c_selinux_contexts_path               :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_securetty_types_path"        c_selinux_securetty_types_path        :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_booleans_path"               c_selinux_booleans_path               :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_customizable_types_path"     c_selinux_customizable_types_path     :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_users_path"                  c_selinux_users_path                  :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_usersconf_path"              c_selinux_usersconf_path              :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_translations_path"           c_selinux_translations_path           :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_colors_path"                 c_selinux_colors_path                 :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_netfilter_context_path"      c_selinux_netfilter_context_path      :: IO CString
foreign import ccall unsafe "selinux/selinux.h selinux_path"                        c_selinux_path                        :: IO CString

