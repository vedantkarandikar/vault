import Route from '@ember/routing/route';
import ClusterRoute from 'vault/mixins/cluster-route';

export default Route.extend(ClusterRoute, {
  model() {

  },
  afterModel() {
    let { client_id, nonce, redirect_uri, response_type, scope, state } = this.paramsFor(this.routeName);
    let { namespaceQueryParam: namespace } = this.paramsFor('vault.cluster');

    console.log(client_id);
    console.log(nonce);
    console.log(redirect_uri);
    console.log(response_type);
    console.log(scope);
    console.log(state);

    let codeReq = this.store.adapterFor('oidc-authorize').oidcAuthorize(client_id, nonce, response_type, scope, redirect_uri, state)

    redirect_uri = window.decodeURIComponent(redirect_uri);

    codeReq.then(resp => {
      console.log('common data', resp);

      // TODO should add error handling and run some validation on this URL
      window.location = redirect_uri + '?nonce=' + nonce + '&state=' + resp.state + '&code=' + resp.code
    });
  },
});
