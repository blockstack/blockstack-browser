import React from 'react'
import { ShellScreen, Shell } from '@blockstack/ui'
import Yup from 'yup'
import PropTypes from 'prop-types'

const validationSchema = Yup.object({
  email: Yup.string()
    .email('Your email address seems invalid.')
    .required('A recovery email is required.')
})

class EmailView extends React.Component {
  returnField = () => [
    {
      type: 'email',
      name: 'email',
      label: 'Email Address',
      message: 'Your email is needed for critical recovery instructions.'
    }
  ]

  render() {
    const { email, updateValue, next, ...rest } = this.props

    const props = {
      title: {
        children: 'What is your email address?',
        variant: 'h2'
      },
      content: {
        grow: 1,
        form: {
          validationSchema,
          validateOnBlur: false,
          initialValues: { email },
          onSubmit: values => {
            updateValue('email', values.email).then(() => next())
          },
          fields: this.returnField(),
          actions: {
            split: true,
            items: [
              {
                label: ' ',
                textOnly: true
              },
              {
                label: 'Next',
                primary: true,
                type: 'submit',
                icon: 'ArrowRightIcon',
                loading: this.props.loading
              }
            ]
          }
        }
      }
    }

    return (
      <React.Fragment>
        {this.props.loading && <Shell.Loading message="Restoring your account..." />}
        <ShellScreen {...rest} {...props} />
      </React.Fragment>
    )
  }
}
EmailView.propTypes = {
  email: PropTypes.string,
  updateValue: PropTypes.func,
  next: PropTypes.func,
  loading: PropTypes.bool
}
export default EmailView
