import * as types from './types'
import { HDNode } from 'bitcoinjs-lib'
import { getBitcoinAddressNode } from '@utils'

const initialState = {
  accountCreated: false, // persist
  promptedForEmail: false, // persist
  email: null, // persist
  encryptedBackupPhrase: null, // persist
  identityAccount: {
    addresses: [],
    keypairs: [],
    settings: []
  },
  bitcoinAccount: {
    addresses: [],
    balances: { total: 0.0 }
  },
  coreWallet: {
    address: null,
    balance: 0.0,
    withdrawal: {
      txHex: null,
      isBuilding: false,
      isBroadcasting: false,
      inProgress: false,
      error: null,
      recipientAddress: null,
      success: false
    }
  },
  viewedRecoveryCode: false, // persist
  recoveryCodeVerified: false,
  connectedStorageAtLeastOnce: false // persist
}

function AccountReducer(state = initialState, action) {
  switch (action.type) {
    case types.CREATE_ACCOUNT:
      return Object.assign({}, state, {
        accountCreated: true,
        encryptedBackupPhrase: action.encryptedBackupPhrase,
        identityAccount: {
          publicKeychain: action.identityPublicKeychain,
          addresses: action.identityAddresses,
          keypairs: action.identityKeypairs,
          settings: action.identitySettings,
          addressIndex: 0
        },
        bitcoinAccount: {
          publicKeychain: action.bitcoinPublicKeychain,
          addresses: [action.firstBitcoinAddress],
          addressIndex: 0,
          balances: state.bitcoinAccount.balances
        }
      })
    case types.UPDATE_EMAIL_ADDRESS:
      return {
        ...state,
        email: action.email
      }
    case types.RECOVERY_CODE_VERIFIED:
      return {
        ...state,
        recoveryCodeVerified: true
      }
    case types.DELETE_ACCOUNT:
      return Object.assign({}, state, {
        accountCreated: false,
        encryptedBackupPhrase: null
      })
    case types.UPDATE_CORE_ADDRESS:
      return Object.assign({}, state, {
        coreWallet: Object.assign({}, state.coreWallet, {
          address: action.coreWalletAddress
        })
      })
    case types.UPDATE_CORE_BALANCE:
      return Object.assign({}, state, {
        coreWallet: Object.assign({}, state.coreWallet, {
          balance: action.coreWalletBalance
        })
      })
    case types.UPDATE_BACKUP_PHRASE:
      return Object.assign({}, state, {
        encryptedBackupPhrase: action.encryptedBackupPhrase
      })
    case types.NEW_BITCOIN_ADDRESS:
      return Object.assign({}, state, {
        bitcoinAccount: {
          publicKeychain: state.bitcoinAccount.publicKeychain,
          addresses: [
            ...state.bitcoinAccount.addresses,
            getBitcoinAddressNode(
              HDNode.fromBase58(state.bitcoinAccount.publicKeychain),
              state.bitcoinAccount.addressIndex + 1
            ).getAddress()
          ],
          addressIndex: state.bitcoinAccount.addressIndex + 1,
          balances: state.bitcoinAccount.balances
        }
      })
    case types.UPDATE_BALANCES:
      return Object.assign({}, state, {
        bitcoinAccount: {
          publicKeychain: state.bitcoinAccount.publicKeychain,
          addresses: state.bitcoinAccount.addresses,
          balances: action.balances
        }
      })
    case types.BUILD_TRANSACTION:
      return {
        ...state,
        coreWallet: {
          ...state.coreWallet,
          withdrawal: {
            txHex: null,
            isBuilding: true,
            isBroadcasting: false,
            inProgress: true,
            error: null,
            success: false,
            recipientAddress: action.payload
          }
        }
      }
    case types.BUILD_TRANSACTION_SUCCESS:
      return {
        ...state,
        coreWallet: {
          ...state.coreWallet,
          withdrawal: {
            ...state.coreWallet.withdrawal,
            txHex: action.payload,
            isBuilding: false
          }
        }
      }
    case types.BUILD_TRANSACTION_ERROR:
      return {
        ...state,
        coreWallet: {
          ...state.coreWallet,
          withdrawal: {
            ...state.coreWallet.withdrawal,
            error: action.payload,
            isBuilding: false,
            inProgress: false
          }
        }
      }
    case types.BROADCAST_TRANSACTION:
      return {
        ...state,
        coreWallet: {
          ...state.coreWallet,
          withdrawal: {
            ...state.coreWallet.withdrawal,
            txHex: action.payload,
            isBroadcasting: true,
            inProgress: true,
            error: null,
            success: false
          }
        }
      }
    case types.BROADCAST_TRANSACTION_SUCCESS:
      return {
        ...state,
        coreWallet: {
          ...state.coreWallet,
          withdrawal: {
            ...state.coreWallet.withdrawal,
            isBroadcasting: false,
            inProgress: false,
            success: true
          }
        }
      }
    case types.BROADCAST_TRANSACTION_ERROR:
      return {
        ...state,
        coreWallet: {
          ...state.coreWallet,
          withdrawal: {
            ...state.coreWallet.withdrawal,
            isBroadcasting: false,
            inProgress: false,
            error: action.payload
          }
        }
      }
    case types.RESET_CORE_BALANCE_WITHDRAWAL:
      return {
        ...state,
        coreWallet: {
          ...state.coreWallet,
          withdrawal: {
            txHex: null,
            isBuilding: false,
            isBroadcasting: false,
            inProgress: false,
            error: null,
            success: false
          }
        }
      }
    case types.WITHDRAWING_CORE_BALANCE:
      return Object.assign({}, state, {
        coreWallet: Object.assign({}, state.coreWallet, {
          withdrawal: {
            txHex: null,
            isBuilding: false,
            isBroadcasting: false,
            inProgress: true,
            error: null,
            success: false,
            recipientAddress: action.recipientAddress
          }
        })
      })
    case types.WITHDRAW_CORE_BALANCE_SUCCESS:
      return Object.assign({}, state, {
        coreWallet: Object.assign({}, state.coreWallet, {
          withdrawal: Object.assign({}, state.coreWallet.withdrawal, {
            inProgress: false,
            success: true
          })
        })
      })
    case types.WITHDRAW_CORE_BALANCE_ERROR:
      return Object.assign({}, state, {
        coreWallet: Object.assign({}, state.coreWallet, {
          withdrawal: Object.assign({}, state.coreWallet.withdrawal, {
            inProgress: false,
            success: false,
            error: action.error
          })
        })
      })
    case types.PROMPTED_FOR_EMAIL:
      return Object.assign({}, state, {
        promptedForEmail: true,
        email: action.email
      })
    case types.VIEWED_RECOVERY_CODE:
      return Object.assign({}, state, {
        viewedRecoveryCode: true
      })
    case types.INCREMENT_IDENTITY_ADDRESS_INDEX:
      return Object.assign({}, state, {
        identityAccount: Object.assign({}, state.identityAccount, {
          addressIndex: state.identityAccount.addressIndex + 1
        })
      })
    case types.NEW_IDENTITY_ADDRESS:
      return Object.assign({}, state, {
        identityAccount: Object.assign({}, state.identityAccount, {
          addresses: [
            ...state.identityAccount.addresses,
            action.keypair.address
          ],
          keypairs: [...state.identityAccount.keypairs, action.keypair],
          settings: [...state.identityAccount.settings, {}]
        })
      })
    case types.CONNECTED_STORAGE:
      return Object.assign({}, state, {
        connectedStorageAtLeastOnce: true
      })
    case types.UPDATE_ALL_IDENTITY_SETTINGS:
      return Object.assign({}, state, {
        identityAccount: Object.assign({}, state.identityAccount, {
          settings: action.settings
        })
      })
    case types.UPDATE_IDENTITY_SETTINGS:
      return Object.assign({}, state, {
        identityAccount: Object.assign({}, state.identityAccount, {
          settings: state.identityAccount.settings.map(
            (settingsRow, i) => i === action.identityIndex ? action.settings : settingsRow
          )
        })
      })
    case types.SET_IDENTITY_COLLECTION_SETTINGS:
      const newIdentitySettings = Object.assign({}, state.identityAccount.settings)

      const identitySettingsAtIndex = newIdentitySettings[action.identityIndex]
      if (!identitySettingsAtIndex.collections) {
        identitySettingsAtIndex.collections = {}
      }
      identitySettingsAtIndex.collections[action.collectionName] = action.collectionSettings

      return Object.assign({}, state, {
        identityAccount: Object.assign({}, state.identityAccount, {
          settings: newIdentitySettings
        })
      })
    default:
      return state
  }
}

export { initialState as AccountInitialState }

export default AccountReducer
