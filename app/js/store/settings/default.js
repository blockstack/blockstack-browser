import { DROPBOX } from '../../storage/utils/index'

// DEFAULT_API values are only used if
// the user's settings.api state doesn't
// already have an existing key.
// To change a value, use a new key.
const DEFAULT_API = {
  apiCustomizationEnabled: true,
  nameLookupUrl: 'http://localhost:6270/v1/names/{name}',
  searchUrl: 'https://api.blockstack.com/v1/search?query={query}',
  registerUrl: 'http://localhost:6270/v1/names',
  addressLookupUrl: 'http://localhost:6270/v1/addresses/{address}',
  addressBalanceUrl: 'https://explorer.blockstack.org/insight-api/addr/{address}/?noTxList=1',
  utxoUrl: 'https://explorer.blockstack.org/insight-api/addr/{address}/utxo',
  broadcastTransactionUrl: 'https://explorer.blockstack.org/insight-api/tx/send',
  priceUrl: 'http://localhost:6270/v1/prices/names/{name}',
  networkFeeUrl: 'https://bitcoinfees.21.co/api/v1/fees/recommended',
  walletPaymentAddressUrl: 'http://localhost:6270/v1/wallet/payment_address',
  pendingQueuesUrl: 'http://localhost:6270/v1/blockchains/bitcoin/pending',
  coreWalletWithdrawUrl: 'http://localhost:6270/v1/wallet/balance',
  bitcoinAddressUrl: 'https://explorer.blockstack.org/address/{identifier}',
  ethereumAddressUrl: 'https://tradeblock.com/ethereum/account/{identifier}',
  pgpKeyUrl: 'https://pgp.mit.edu/pks/lookup?search={identifier}&op=vindex&fingerprint=on',
  btcPriceUrl: 'https://www.bitstamp.net/api/v2/ticker/btcusd/',
  hostedDataLocation: DROPBOX,
  coreAPIPassword: null,
  logServerPort: '',
  s3ApiKey: '',
  s3ApiSecret: '',
  s3Bucket: '',
  dropboxAccessToken: null,
  btcPrice: '1000.00'
}

export default DEFAULT_API
