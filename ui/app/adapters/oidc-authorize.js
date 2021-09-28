import ApplicationAdapter from './application';

export default ApplicationAdapter.extend({
  oidcAuthorize(client_id, nonce, response_type, scope, redirect_uri, state) {
    return this.ajax(this.urlForUpdateRecord(), 'POST', {
      data: {
        'client_id': client_id,
        'response_type': response_type,
        'scope': scope,
        'nonce': nonce,
        'redirect_uri': redirect_uri,
        'state': state,
      },
    });
  },
  urlForUpdateRecord() {
    return '/v1/identity/oidc/provider/my-provider/authorize';
  },
});
