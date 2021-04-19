module KeyReveal ( revealKeys ) where

import qualified Data.Bit                  as BI (cloneFromByteString, Bit (unBit))
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Random    as R
import qualified Data.ByteString.UTF8      as BSU
import qualified Data.Vector               as V

import LamUtils ( hash, bits )
import Lamport
    ( sign, generateKey, KeyPair(_private), HashPair(..) )

{-| Simulates breaking the Lamport scheme using only
    successive invocations of 'sign' as a means to do so. -}
revealKeys :: IO [HashPair]
revealKeys = do
  original <- generateKey
  seed <- R.random 32                                               -- seed a value to reveal private keys.
  let originalP = _private original                                 -- original private keys.
  let cleared = map (const $ HashPair BS.empty BS.empty) originalP  -- a cleared instance of the keys.
  let sigGen = sign originalP                                       -- function to sign w/ original keyset.
  -- original & cleared lists are setup, begin cracking lamport
  return $ reveal cleared (BSU.toString seed) sigGen
  where bothPopulated = \h -> _0 h /= BS.empty && _1 h /= BS.empty
        reveal keys msg gen =
          if all bothPopulated keys
          then keys
          else let sig'  = gen msg                                  -- generate a signature.
                   msgBits = V.toList $ bits (BSU.fromString msg)   -- get a list of bits in the message.
                   next  = BSU.toString $ hash $ BSU.fromString msg -- hash to get the next pseudo-random message.
                   keys' = zipWith3 fillEmpty msgBits sig' keys     -- fill any keys that were obtained through this round.
                   fillEmpty bit chunk pair =
                     if BI.unBit bit
                     then HashPair (_0 pair) chunk
                     else HashPair chunk (_1 pair)
               in reveal keys' next gen
