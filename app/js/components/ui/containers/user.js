import React from 'react'
import PropTypes from 'prop-types'
import { Button, firstLetter, stringToColor, Type } from '@blockstack/ui'
import { User } from '@blockstack/ui/components/user'
import { ChevronRightIcon } from 'mdi-react'
import Image from '@components/Image'

const UserAvatar = ({
  id,
  username = '?',
  size = 46,
  camera,
  textSize = 14,
  avatarUrl = '',
  ...rest
}) => (
  <User.Avatar
    size={size}
    color={stringToColor(id)}
    textSize={textSize}
    camera={camera}
    {...rest}
  >
    {avatarUrl ? (
      <Image
        src={avatarUrl}
        fallbackSrc="/images/avatar.png"
        className="rounded-circle img-cover"
        style={{
          display: 'inline-block',
          width: '100%',
          height: '100%'
        }}
      />
    ) : (
      <span>{firstLetter(username)}</span>
    )}
    {camera && <User.Avatar.Camera />}
  </User.Avatar>
)

const UserButton = ({ username, id, hideID, avatarUrl, ...rest }) => (
  <Button height={56} primary padding="5px" {...rest}>
    <Button.Section>
      <UserAvatar
        username={username}
        avatarUrl={avatarUrl}
        id={id}
      />
    </Button.Section>
    <Button.Section
      grow
      column
      padding="0 10px"
      align="flex-start"
      justify="center"
      cd
      maxWidth="calc(100% - 102px) !important"
    >
      <Type.p color="rgba(255,255,255,1)" overflow>
        {username.includes('.') ? (
          <React.Fragment>
            <span style={{ color: 'rgba(255,255,255,1)' }}>
              {username.substr(0, username.indexOf('.'))}
            </span>
            <span style={{ color: 'rgba(255,255,255,0.5' }}>
              .{username
                .split('.')
                .slice(1)
                .join('.')}
            </span>
          </React.Fragment>
        ) : (
          <span style={{ color: 'rgba(255,255,255,1)' }}>{username}</span>
        )}
      </Type.p>
      {id &&
        !hideID && <Type.small color="rgba(255,255,255,0.5)">{id}</Type.small>}
    </Button.Section>
    <Button.Section align="center" justify="center" padding="0 10px 0 10px">
      <ChevronRightIcon size={24} color="white" />
    </Button.Section>
  </Button>
)

UserAvatar.propTypes = {
  id: PropTypes.string,
  username: PropTypes.string,
  size: PropTypes.number,
  camera: PropTypes.bool,
  textSize: PropTypes.number,
  avatarUrl: PropTypes.string
}
UserButton.propTypes = {
  id: PropTypes.string,
  username: PropTypes.string,
  hideID: PropTypes.bool,
  avatarUrl: PropTypes.string
}
export { UserButton, UserAvatar }
