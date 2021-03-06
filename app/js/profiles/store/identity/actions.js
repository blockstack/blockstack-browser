import { bip32 } from 'bitcoinjs-lib'
import * as bip39 from 'bip39'
import * as cheerio from 'cheerio'
import * as types from './types'
import { validateProofs } from 'blockstack'
import {
  authorizationHeaderValue,
  decrypt,
  deriveIdentityKeyPair,
  getIdentityOwnerAddressNode,
  getIdentityPrivateKeychain,
  resolveZoneFileToProfile
} from '../../../utils'
import { DEFAULT_PROFILE, fetchProfileLocations } from '../../../utils/profile-utils'
import { calculateTrustLevel } from '../../../utils/account-utils'
import AccountActions from '../../../account/store/account/actions'
import { isWebAppBuild } from '../../../utils/window-utils'


import log4js from 'log4js'

const logger = log4js.getLogger(__filename)

function validateProofsService(
  profile,
  address,
  username = null
) {
  if (!isWebAppBuild()) {
    return validateProofs(profile, address, cheerio, username)
  }

  const args = {
    profile,
    address
  }
  if (username !== null && username !== undefined) {
    args.username = username
  }
  return fetch('https://proofs.blockstack.org/validate/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(args)
  }).then(resp => resp.json())
}

/**
 *  username
 *  ownerAddress
 *  zoneFile
 *  profile
 *  verifications
 *  trustLevel
 *
 */
function updatePublicIdentity(
  username,
  ownerAddress = null,
  zoneFile = null,
  profile = Object.assign({}, DEFAULT_PROFILE),
  verifications = [],
  trustLevel = 0
) {
  return {
    type: types.UPDATE_PUBLIC_IDENTITY,
    username,
    ownerAddress,
    zoneFile,
    profile,
    verifications,
    trustLevel
  }
}

function setDefaultIdentity(index) {
  return {
    type: types.SET_DEFAULT,
    index
  }
}

function createNewIdentity(index, ownerAddress) {
  return {
    type: types.CREATE_NEW_SUCCESS,
    index,
    ownerAddress
  }
}

function createNewProfileError(error) {
  return {
    type: types.CREATE_NEW_ERROR,
    error
  }
}

function resetCreateNewProfileError() {
  return {
    type: types.CREATE_NEW_ERROR_RESET
  }
}

function usernameOwned(index, username) {
  return {
    type: types.USERNAME_OWNED,
    index,
    username
  }
}

function noUsernameOwned(index) {
  return {
    type: types.NO_USERNAME_OWNED,
    index
  }
}

function updateProfile(index, profile, zoneFile, expireBlock) {
  return {
    type: types.UPDATE_PROFILE,
    index,
    profile,
    zoneFile,
    expireBlock
  }
}

function updateSocialProofVerifications(
  index,
  verifications,
  trustLevel
) {
  return {
    type: types.UPDATE_SOCIAL_PROOF_VERIFICATIONS,
    index,
    verifications,
    trustLevel
  }
}

function addUsername(index, username) {
  return {
    type: types.ADD_USERNAME,
    index,
    username
  }
}

function broadcastingZoneFileUpdate(domainName) {
  return {
    type: types.BROADCASTING_ZONE_FILE_UPDATE,
    domainName
  }
}

function broadcastedZoneFileUpdate(domainName) {
  return {
    type: types.BROADCASTED_ZONE_FILE_UPDATE,
    domainName
  }
}

function broadcastingZoneFileUpdateError(domainName, error) {
  return {
    type: types.BROADCASTING_ZONE_FILE_UPDATE_ERROR,
    domainName,
    error
  }
}

function broadcastingNameTransfer(domainName) {
  return {
    type: types.BROADCASTING_NAME_TRANSFER,
    domainName
  }
}

function broadcastedNameTransfer(domainName) {
  return {
    type: types.BROADCASTED_NAME_TRANSFER,
    domainName
  }
}

function broadcastingNameTransferError(domainName, error) {
  return {
    type: types.BROADCASTING_NAME_TRANSFER_ERROR,
    domainName,
    error
  }
}

function createNewIdentityWithOwnerAddress(
  index,
  ownerAddress
) {
  logger.debug(
    `createNewIdentityWithOwnerAddress: index: ${index} address: ${ownerAddress}`
  )
  return (dispatch) => {
    dispatch(createNewIdentity(index, ownerAddress))
    dispatch(AccountActions.usedIdentityAddress())
  }
}

function createNewProfile(
  encryptedBackupPhrase,
  password,
  nextUnusedAddressIndex
) {
  return async (dispatch, getState) => {
    logger.info('createNewProfile')

    const state = getState()
    if (
      state.profiles &&
      state.profiles.identity &&
      state.profiles.identity.isProcessing
    ) {
      logger.info('createNewProfile: Early exit because isProcessing')
      return Promise.resolve()
    }

    logger.info('createNewProfile: Dispatch CREATE_NEW_REQUEST')
    dispatch({ type: types.CREATE_NEW_REQUEST })

    // Decrypt master keychain
    const dataBuffer = Buffer.from(encryptedBackupPhrase, 'hex')
    logger.debug('createNewProfile: Trying to decrypt backup phrase...')
    return decrypt(dataBuffer, password).then(
      async plaintextBuffer => {
        logger.debug('createNewProfile: Backup phrase successfully decrypted')
        const backupPhrase = plaintextBuffer.toString()
        const seedBuffer = await bip39.mnemonicToSeed(backupPhrase)
        const masterKeychain = bip32.fromSeed(seedBuffer)
        const identityPrivateKeychainNode = getIdentityPrivateKeychain(
          masterKeychain
        )
        const index = nextUnusedAddressIndex
        const identityOwnerAddressNode = getIdentityOwnerAddressNode(
          identityPrivateKeychainNode,
          index
        )
        const newIdentityKeypair = deriveIdentityKeyPair(
          identityOwnerAddressNode
        )
        logger.debug(
          `createNewProfile: new identity: ${newIdentityKeypair.address}`
        )
        dispatch(AccountActions.newIdentityAddress(newIdentityKeypair))
        const ownerAddress = newIdentityKeypair.address
        // $FlowFixMe
        dispatch(createNewIdentityWithOwnerAddress(index, ownerAddress))
      },
      () => {
        logger.error('createNewProfile: Invalid password')
        dispatch(createNewProfileError('Your password is incorrect.'))
      }
    )
  }
}

/**
 * Checks each owner address to see if it owns a name, if it owns a name,
 * it resolves the profile and updates the state with the owner address's
 * current name.
 *
 * If it doesn't have a name, check default gaia storage for a profile
 *
 */
function refreshIdentities(
  api,
  ownerAddresses
) {
  return async (dispatch) => {
    logger.info('refreshIdentities')

    const promises = ownerAddresses.map((address, index) => {
      const promise = new Promise(resolve => {
        const url = api.bitcoinAddressLookupUrl.replace('{address}', address)
        logger.debug(`refreshIdentities: fetching ${url}`)
        return fetch(url)
          .then(response => response.text())
          .then(responseText => JSON.parse(responseText))
          .then(responseJson => {
            if (responseJson.names.length === 0) {
              logger.debug(
                `refreshIdentities: ${address} owns no names, checking default locations.`
              )
              const gaiaBucketAddress = ownerAddresses[0]
              return fetchProfileLocations(
                api.gaiaHubConfig.url_prefix,
                address,
                gaiaBucketAddress,
                index
              ).then(returnObject => {
                if (returnObject && returnObject.profile) {
                  const profile = returnObject.profile
                  const zoneFile = ''
                  dispatch(updateProfile(index, profile, zoneFile))
                  let verifications = []
                  let trustLevel = 0
                  logger.debug(
                    `refreshIdentities: validating address proofs for ${address}`
                  )
                  return validateProofsService(profile, address)
                    .then(proofs => {
                      verifications = proofs
                      trustLevel = calculateTrustLevel(verifications)
                      dispatch(
                        updateSocialProofVerifications(
                          index,
                          verifications,
                          trustLevel
                        )
                      )
                      resolve()
                    })
                    .catch(error => {
                      logger.error(
                        `refreshIdentities: ${address} validateProofs: error`,
                        error
                      )
                      resolve()
                    })
                } else {
                  resolve()
                  return Promise.resolve()
                }
              })
            } else {
              if (responseJson.names.length === 1) {
                logger.debug(`refreshIdentities: ${address} has 1 name}`)
              } else {
                logger.debug(
                  `refreshIdentities: ${address} has multiple names. Only using 0th.`
                )
              }
              const nameOwned = responseJson.names[0]
              dispatch(usernameOwned(index, nameOwned))
              logger.debug(
                `refreshIdentities: Preparing to resolve profile for ${nameOwned}`
              )
              const lookupUrl = api.nameLookupUrl.replace('{name}', nameOwned)
              logger.debug(`refreshIdentities: fetching: ${lookupUrl}`)
              return fetch(lookupUrl)
                .then(response => response.text())
                .then(responseText => JSON.parse(responseText))
                .then(lookupResponseJson => {
                  const zoneFile = lookupResponseJson.zonefile
                  const ownerAddress = lookupResponseJson.address
                  const expireBlock = lookupResponseJson.expire_block || -1
                  logger.debug(
                    `refreshIdentities: resolving zonefile of ${nameOwned} to profile`
                  )
                  return resolveZoneFileToProfile(zoneFile, ownerAddress)
                    .then(profile => {
                      if (profile) {
                        dispatch(
                          updateProfile(index, profile, zoneFile, expireBlock)
                        )
                        let verifications = []
                        let trustLevel = 0
                        return validateProofsService(
                          profile,
                          ownerAddress,
                          nameOwned
                        )
                          .then(proofs => {
                            verifications = proofs
                            trustLevel = calculateTrustLevel(verifications)
                            dispatch(
                              updateSocialProofVerifications(
                                index,
                                verifications,
                                trustLevel
                              )
                            )
                            resolve()
                          })
                          .catch(error => {
                            logger.error(
                              `refreshIdentities: ${nameOwned} validateProofs: error`,
                              error
                            )
                            return Promise.resolve()
                          })
                      }
                      resolve()
                      return Promise.resolve()
                    })
                    .catch(error => {
                      logger.error(
                        `refreshIdentities: resolveZoneFileToProfile for ${nameOwned} error`,
                        error
                      )
                      dispatch(updateProfile(index, DEFAULT_PROFILE, zoneFile))
                      resolve()
                      return Promise.resolve()
                    })
                })
                .catch(error => {
                  logger.error('refreshIdentities: name lookup: error', error)
                  resolve()
                  return Promise.resolve()
                })
            }
          })
          .catch(error => {
            logger.error('refreshIdentities: addressLookup: error', error)
            resolve()
            return Promise.resolve()
          })
      })
      return promise
    })
    return Promise.all(promises)
  }
}

function refreshSocialProofVerifications(
  identityIndex,
  ownerAddress,
  username,
  profile
) {
  return (dispatch) =>
    new Promise(resolve => {
      let verifications = []
      let trustLevel = 0
      validateProofsService(profile, ownerAddress, username)
        .then(proofs => {
          verifications = proofs
          trustLevel = calculateTrustLevel(verifications)
          dispatch(
            updateSocialProofVerifications(
              identityIndex,
              verifications,
              trustLevel
            )
          )
          resolve()
        })
        .catch(error => {
          logger.error(
            `refreshSocialProofVerifications: index ${identityIndex} proofs error`,
            error
          )
          dispatch(
            updateSocialProofVerifications(identityIndex, [], trustLevel)
          )
          resolve()
        })
    })
}

/**
 * Resolves a Blockstack ID username to zonefile, fetches the profile file,
 * validates proofs and then stores the results in the identity store in an
 * object under the key publicIdentities.
 *
 * @param  {String} lookupUrl name look up endpoint
 * @param  {String} username  the username of the Blockstack ID to fetch
 */
function fetchPublicIdentity(lookupUrl, username) {
  return (dispatch) => {
    const url = lookupUrl.replace('{name}', username)
    return fetch(url)
      .then(response => response.text())
      .then(responseText => JSON.parse(responseText))
      .then(responseJson => {
        const zoneFile = responseJson.zonefile
        const ownerAddress = responseJson.address

        return resolveZoneFileToProfile(zoneFile, ownerAddress)
          .then(profile => {
            let verifications = []
            let trustLevel = 0
            dispatch(
              updatePublicIdentity(
                username,
                ownerAddress,
                zoneFile,
                profile,
                verifications,
                trustLevel
              )
            )
            if (profile) {
              return validateProofsService(profile, ownerAddress, username)
                .then(proofs => {
                  verifications = proofs
                  trustLevel = calculateTrustLevel(verifications)
                  dispatch(
                    updatePublicIdentity(
                      username,
                      ownerAddress,
                      zoneFile,
                      profile,
                      verifications,
                      trustLevel
                    )
                  )
                })
                .catch(error => {
                  logger.error(
                    `fetchPublicIdentity: ${username} validateProofs: error`,
                    error
                  )
                  return Promise.resolve()
                })
            } else {
              logger.debug('fetchPublicIdentity: no profile')
              dispatch(updatePublicIdentity(username, ownerAddress, zoneFile))
              return Promise.resolve()
            }
          })
          .catch(error => {
            logger.error(
              `fetchPublicIdentity: ${username} resolveZoneFileToProfile: error`,
              error
            )
            dispatch(updatePublicIdentity(username, ownerAddress, zoneFile))
          })
      })
      .catch(error => {
        dispatch(updatePublicIdentity(username))
        logger.error(`fetchPublicIdentity: ${username} lookup error`, error)
      })
  }
}

function broadcastZoneFileUpdate(
  zoneFileUrl,
  coreAPIPassword,
  name,
  keypair,
  zoneFile
) {
  logger.info('broadcastZoneFileUpdate: entering')
  return (dispatch) => {
    dispatch(broadcastingZoneFileUpdate(name))
    // Core registers with an uncompressed address,
    // browser expects compressed addresses,
    // we need to add a suffix to indicate to core
    // that it should use a compressed addresses
    // see https://en.bitcoin.it/wiki/Wallet_import_format
    // and https://github.com/blockstack/blockstack-browser/issues/607
    const compressedPublicKeySuffix = '01'
    const coreFormatOwnerKey = `${keypair.key}${compressedPublicKeySuffix}`
    const url = zoneFileUrl.replace('{name}', name)
    const requestHeaders = {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      Authorization: authorizationHeaderValue(coreAPIPassword)
    }
    const ownerKey = coreFormatOwnerKey
    const requestBody = JSON.stringify({
      owner_key: ownerKey,
      zonefile: zoneFile
    })
    logger.debug(`broadcastZoneFileUpdate: PUT to ${url}`)
    return fetch(url, {
      method: 'PUT',
      headers: requestHeaders,
      body: requestBody
    })
      .then(response => {
        if (response.ok) {
          dispatch(broadcastedZoneFileUpdate(name))
        } else {
          response
            .text()
            .then(responseText => JSON.parse(responseText))
            .then(responseJson => {
              const error = responseJson.error
              logger.error('broadcastZoneFileUpdate: error', error)
              dispatch(broadcastingZoneFileUpdateError(name, error))
            })
        }
      })
      .catch(error => {
        logger.error('broadcastZoneFileUpdate: error', error)
        dispatch(broadcastingZoneFileUpdateError(name, error))
      })
  }
}

function broadcastNameTransfer(
  nameTransferUrl,
  coreAPIPassword,
  name,
  keypair,
  newOwnerAddress
) {
  logger.info('broadcastNameTransfer: entering')
  return (dispatch) => {
    dispatch(broadcastingNameTransfer(name))
    // Core registers with an uncompressed address,
    // browser expects compressed addresses,
    // we need to add a suffix to indicate to core
    // that it should use a compressed addresses
    // see https://en.bitcoin.it/wiki/Wallet_import_format
    // and https://github.com/blockstack/blockstack-browser/issues/607
    const compressedPublicKeySuffix = '01'
    const coreFormatOwnerKey = `${keypair.key}${compressedPublicKeySuffix}`
    const url = nameTransferUrl.replace('{name}', name)
    const requestHeaders = {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      Authorization: authorizationHeaderValue(coreAPIPassword)
    }
    const ownerKey = coreFormatOwnerKey
    const requestBody = JSON.stringify({
      owner_key: ownerKey,
      owner: newOwnerAddress
    })
    logger.debug(`broadcastNameTransfer: PUT to ${url}`)
    return fetch(url, {
      method: 'PUT',
      headers: requestHeaders,
      body: requestBody
    })
      .then(response => {
        if (response.ok) {
          dispatch(broadcastedNameTransfer(name))
        } else {
          response
            .text()
            .then(responseText => JSON.parse(responseText))
            .then(responseJson => {
              const error = responseJson.error
              logger.error('broadcastNameTransfer: error', error)
              dispatch(broadcastingNameTransferError(name, error))
            })
        }
      })
      .catch(error => {
        logger.error('broadcastZoneFileUpdate: error', error)
        dispatch(broadcastingNameTransferError(name, error))
      })
  }
}

const IdentityActions = {
  updatePublicIdentity,
  setDefaultIdentity,
  createNewIdentity,
  createNewIdentityWithOwnerAddress,
  createNewProfile,
  updateProfile,
  fetchPublicIdentity,
  refreshIdentities,
  refreshSocialProofVerifications,
  addUsername,
  usernameOwned,
  noUsernameOwned,
  createNewProfileError,
  resetCreateNewProfileError,
  broadcastingZoneFileUpdate,
  broadcastedZoneFileUpdate,
  broadcastingZoneFileUpdateError,
  broadcastZoneFileUpdate,
  broadcastingNameTransfer,
  broadcastedNameTransfer,
  broadcastingNameTransferError,
  broadcastNameTransfer
}

export default IdentityActions
