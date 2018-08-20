import configureStore from './configure'

function checkForLegacyReduxData() {
  const data = localStorage.getItem('redux')
  console.debug('persted data exists: ', JSON.parse(data))
  if (!data) {
    console.log('no data, continue')
    return null
  }

  const parsedData = JSON.parse(data)
  const { computedStates, currentStateIndex } = parsedData
  if (!computedStates) {
    console.debug('no computed states')
    return null
  }
  const lastState = computedStates[currentStateIndex]
    ? computedStates[currentStateIndex].state
    : undefined

  if (computedStates && lastState) {
    console.debug('computed states and last state', lastState)
    localStorage.setItem('redux', JSON.stringify(lastState))
    localStorage.setItem('redux_old', JSON.stringify(parsedData))
    console.log('finished, returning object')
    return lastState
  }

  return null
}

const legacyStore = checkForLegacyReduxData()
console.log('legacystore', legacyStore)
const store = configureStore(legacyStore)

export default store
