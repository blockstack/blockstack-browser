import React, { Component, PropTypes } from 'react'
import { bindActionCreators } from 'redux'
import { connect } from 'react-redux'
import { Link } from 'react-router'
import { PrivateKeychain, PublicKeychain } from 'blockstack-keychains'

import EditProfileHeader from './components/EditProfileHeader'
import ProfileEditingSidebar from './components/ProfileEditingSidebar'
import { IdentityActions } from '../store/identities'
import { signProfileForUpload, getNameParts } from '../utils/index'
import { uploadProfile, uploadPhoto } from '../storage/utils'

import BasicInfoTab      from './tabs/BasicInfoTab'
import PhotosTab         from './tabs/PhotosTab'
import SocialAccountsTab from './tabs/SocialAccountsTab'
import PublicKeysTab     from './tabs/PublicKeysTab'
import PrivateInfoTab    from './tabs/PrivateInfoTab'

function mapStateToProps(state) {
  return {
    localIdentities: state.identities.localIdentities,
    api: state.settings.api,
    identityKeypairs: state.account.identityAccount.keypairs
  }
}

function mapDispatchToProps(dispatch) {
  return bindActionCreators(IdentityActions, dispatch)
}

class EditProfilePage extends Component {
  static propTypes = {
    updateProfile: PropTypes.func.isRequired,
    localIdentities: PropTypes.object.isRequired,
    api: PropTypes.object.isRequired,
    identityKeypairs: PropTypes.array.isRequired
  }

  constructor(props) {
    super(props)

    this.state = {
      domainName: null,
      profile: null,
      profileJustSaved: false,
      verifications: [],
      tabName: "Basic Info"
    }

    this.saveProfile = this.saveProfile.bind(this)
    this.changeTabs = this.changeTabs.bind(this)
    this.uploadProfilePhoto = this.uploadProfilePhoto.bind(this)
  }

  componentHasNewLocalIdentities(props) {
    const profileIndex = this.props.routeParams.index
    if (props.localIdentities[profileIndex]) {
      const newDomainName = props.localIdentities[profileIndex].domainName
      const newProfile = props.localIdentities[profileIndex].profile
      if (profileIndex) {
        this.setState({
          domainName: newDomainName,
          profile: newProfile
        })
      }
    } else {
      // Do nothing
    }
  }

  componentWillMount() {
    this.componentHasNewLocalIdentities(this.props)
  }

  componentWillReceiveProps(nextProps) {
    if (nextProps.localIdentities !== this.props.localIdentities) {
      this.componentHasNewLocalIdentities(nextProps)
    }
  }

  componentWillUnmount() {
    this.saveProfile(this.state.profile)
  }

  saveProfile(newProfile) {
    this.props.updateProfile(this.props.routeParams.index, newProfile)

    const data = signProfileForUpload(this.state.profile, this.props.identityKeypairs[0])

    uploadProfile(this.props.api, this.state.domainName, data).catch((err) => {
      console.error(err)
      console.error('profile not uploaded')
    })
  }


  uploadProfilePhoto(file, index) {
    const name = this.state.domainName
    return uploadPhoto(this.props.api, name, file, index)
  }

  changeTabs(tabName) {
    this.setState({tabName: tabName})
  }

  render() {
    return (
      <div className="card-list-container profile-content-wrapper">
        {this.state.profile && this.state.domainName ?
        <div>
          <EditProfileHeader title="Edit Profile"/>
          <div className="vertical-split-content">
            <div className="row">
              <div className="col-md-3 sidebar-list">
                <ProfileEditingSidebar
                  activeTab={this.state.tabName}
                  onClick={this.changeTabs} />
                <hr />
                <div className="form-group">
                  <fieldset>
                    <Link to={this.props.location.pathname.replace('/edit', '/local')}
                      className="btn btn-primary">
                      Save + View Profile
                    </Link>
                  </fieldset>
                </div>
              </div>
              <div className="col-md-7">
                { this.state.profile ? (
                <div>
                  {(() => {
                    switch (this.state.tabName) {
                      case "Basic Info":
                        return (
                          <BasicInfoTab
                            profile={this.state.profile}
                            saveProfile={this.saveProfile} />
                        )
                      case "Photos":
                        return (
                          <PhotosTab
                            profile={this.state.profile}
                            saveProfile={this.saveProfile}
                            uploadProfilePhoto={this.uploadProfilePhoto} />
                        )
                      case "Social Accounts":
                        return (
                          <SocialAccountsTab
                            profile={this.state.profile}
                            saveProfile={this.saveProfile}
                            domainName={this.state.domainName} />
                        )
                      case "Address":
                        return (
                          <PrivateInfoTab
                            profile={this.state.profile}
                            saveProfile={this.saveProfile} />
                        )
                      case "Digital Keys":
                        return (
                          <PublicKeysTab
                            profile={this.state.profile}
                            saveProfile={this.saveProfile}
                            domainName={this.state.domainName} />
                        )
                      default:
                        return (
                          <div></div>
                        )
                    }
                  })()}
                </div>
                ) : null }
              </div>
            </div>
          </div>
        </div>
        :
        <div>
          <h1 className="h1-modern vertical-split-content">
            Page Not Found
          </h1>
          <p>You don't own this profile and therefore you cannot edit it.</p>
        </div>
        }
      </div>
    )
  }
}

export default connect(mapStateToProps, mapDispatchToProps)(EditProfilePage)
