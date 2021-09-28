import Controller from '@ember/controller';

export default Controller.extend({
  queryParams: ['client_id', 'nonce', 'redirect_uri', 'response_type', 'scope', 'state'],
  client_id: null,
  nonce: null,
  redirect_uri: null,
  response_type: null,
  scope: null,
  state: null,
});
