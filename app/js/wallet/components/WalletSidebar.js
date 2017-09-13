import React, { Component, PropTypes } from 'react'
import { Link } from 'react-router'

class WalletSidebar extends Component {
  static propTypes = {
    activeTab: PropTypes.string,
  }

  render() {
    const tabs = [
      { url: '/wallet/receive', label: 'receive', isActive: false },
      { url: '/wallet/send', label: 'send', isActive: false },
    ]
    tabs.map((tab) => {
      if (tab.url === this.props.activeTab) {
        tab.isActive = true
      }
    })

    return (
      <div className="list-group">
        {tabs.map((tab, index) => {
          let className = 'list-group-item item-sidebar-wallet'
          if (tab.isActive) {
            className += ' active'
          }
          return (
            <Link key={index} to={tab.url} className={className}>
              {tab.label}
            </Link>
          )
        })}
      </div>
    )
  }
}

export default WalletSidebar
