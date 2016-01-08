var Bell = require('bell');
var AuthCookie = require('hapi-auth-cookie');
var Promise = require('bluebird');
var request = Promise.promisify(require('request'));
var uuid = require('uuid');

module.exports = function (kibana) {
  return new kibana.Plugin({
  /*
  This will set the name of the plugin and will be used by the server for
  namespacing purposes in the configuration. In Hapi you can expose methods and
  objects to the system via `server.expose()`. Access to these attributes are done
  via `server.plugins.<name>.<attribute>`. See the `elasticsearch` plugin for an
  example of how this is done. If you omit this attribute then the plugin loader
  will try to set it to the name of the parent folder.
  */
  name: 'authentication',

  /*
  This is an array of plugin names this plugin depends on. These are guaranteed
  to load before the init() method for this plugin is executed.
  */
  require: [],

  /*
  This method is executed to create a Joi schema for the plugin.
  The Joi module is passed to every config method and config methods can return promises
  if they need to execute an async operation before setting the defaults. If you're
  returning a promise then you should resolve the promise with the Joi schema.
  */
  config: function (Joi) {
    var client_id = (process.env.KIBANA_OAUTH2_CLIENT_ID) ? process.env.KIBANA_OAUTH2_CLIENT_ID : 'client_id';
    var client_secret = (process.env.KIBANA_OAUTH2_CLIENT_SECRET) ? process.env.KIBANA_OAUTH2_CLIENT_SECRET : 'client_secret';
    var client_scope = (process.env.KIBANA_OAUTH_CLIENT_SCOPE) ? process.env.KIBANA_OAUTH_CLIENT_SCOPE : '';
    var skip_ssl_validation = (process.env.SKIP_SSL_VALIDATION) ? (process.env.SKIP_SSL_VALIDATION.toLowerCase() === 'true') : false;
    var cf_system_org = (process.env.CF_SYSTEM_ORG) ? process.env.CF_SYSTEM_ORG : 'system';
    var cloudFoundryApiUri = (process.env.CF_API_URI) ? process.env.CF_API_URI.replace(/\/$/, '') : 'unknown';
    var cfInfoUri = cloudFoundryApiUri + '/v2/info';

    if (skip_ssl_validation) {
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    }

    //Fetch location of login server, then set config
    return request(cfInfoUri).spread(function (response, body) {

      var cf_info = JSON.parse(body);

      return Joi.object({
        enabled: Joi.boolean().default(true),
        client_id: Joi.string().default(client_id),
        client_secret: Joi.string().default(client_secret),
        skip_ssl_validation: Joi.boolean().default(skip_ssl_validation),
        cf_system_org: Joi.string().default(cf_system_org),
        authorization_uri: Joi.string().default(cf_info.authorization_endpoint + '/oauth/authorize'),
        logout_uri: Joi.string().default(cf_info.authorization_endpoint + '/logout.do'),
        token_uri: Joi.string().default(cf_info.token_endpoint + '/oauth/token'),
        account_info_uri: Joi.string().default(cf_info.token_endpoint + '/userinfo'),
        organizations_uri: Joi.string().default(cloudFoundryApiUri + '/v2/organizations'),
        spaces_uri: Joi.string().default(cloudFoundryApiUri + '/v2/spaces'),
        random_passphrase: Joi.string().default(uuid.v4())
      }).default();

    }).catch(function (error) {
      console.log('ERROR fetching CF info from ' + cfInfoUri + ' : ' + error);
      return Joi.object({
        enabled: Joi.boolean().default(true)
      }).default();
    });

  },

  /*
  The init method is where all the magic happens. It's essentially the same as the
  register method for a Hapi plugin except it uses promises instead of a callback
  pattern. Just return a promise when you execute an async operation.
  */
  init: function (server, options) {
    var config = server.config();

    server.log(['debug', 'authentication'], JSON.stringify(config.get('authentication')));

    server.register([Bell, AuthCookie], function (err) {

      if (err) {
        server.log(['error', 'authentication'], JSON.stringify(err));
        return;
      }

      var cache = server.cache({ segment: 'sessions', expiresIn: 30 * 60 * 1000 });
      server.app.cache = cache;

      server.auth.strategy('uaa-cookie', 'cookie', {
        password: config.get('authentication.random_passphrase'), //Password used for encryption
        cookie: 'uaa-auth', // Name of cookie to set
        redirectTo: '/login',
        validateFunc: function(request, session, callback) {
          cache.get(session.session_id, function(err, cached) {
            if (err) {
              server.log(['error', 'session', 'validation'], JSON.stringify(err));
              return callback(err, false);
            }
            if (!cached) {
              return callback(null, false);
            }
            return callback(null, true, cached.credentials);
          });
        }
      });

      var uaaProvider = {
        protocol: 'oauth2',
        auth: config.get('authentication.authorization_uri'),
        token: config.get('authentication.token_uri'),
        scope: ['openid', 'oauth.approvals', 'scim.userids', 'cloud_controller.read'],
        profile: function (credentials, params, get, callback) {
          server.log(['debug', 'authentication'],  JSON.stringify({ thecredentials: credentials, theparams: params }));
          get(config.get('authentication.account_info_uri'), null, function (profile) {
            server.log(['debug', 'authentication'], JSON.stringify({ theprofile: profile }));
            credentials.profile = {
              id: profile.id,
              username: profile.username,
              displayName: profile.name,
              email: profile.email,
              raw: profile
            };

            get(config.get('authentication.organizations_uri'), null, function(orgs) {
              server.log(['debug', 'authentication', 'orgs'], JSON.stringify(orgs));
              credentials.orgIds = orgs.resources.map(function(resource) { return resource.metadata.guid; });
              credentials.orgs = orgs.resources.map(function(resource) { return resource.entity.name; });

              get(config.get('authentication.spaces_uri'), null, function(spaces) {
                server.log(['debug', 'authentication', 'spaces'], JSON.stringify(spaces));
                credentials.spaceIds = spaces.resources.map(function(resource) { return resource.metadata.guid; });
                credentials.spaces = spaces.resources.map(function(resource) { return resource.entity.name; });
                return callback();
              });
            });
          });
        }
      };

      server.auth.strategy('uaa-oauth', 'bell', {
        provider: uaaProvider,
        password: config.get('authentication.random_passphrase'), //Password used for encryption
        clientId: config.get('authentication.client_id'),
        clientSecret: config.get('authentication.client_secret'),
        forceHttps: true
      });

      server.auth.default('uaa-cookie');

      server.route([{
          method: 'GET',
          path: '/login',
          config: {
            auth: 'uaa-oauth',
            handler: function (request, reply) {
              if (request.auth.isAuthenticated) {
                var credentials = request.auth.credentials;
                credentials.session_id = uuid.v1();
                request.server.app.cache.set(credentials.session_id, {credentials: credentials}, 0, function(err) {
                  if (err) {
                    server.log(['error', 'session', 'cache'], JSON.stringify(err));
                    reply(err);
                  }
                  request.auth.session.set(credentials);
                  return reply.redirect('/');
                });
              } else {
                reply('Not logged in...').code(401);
              }
            }
          }
        }, {
          method: 'GET',
          path: '/account',
          config: {
            handler: function (request, reply) {
              reply(request.auth.credentials.profile);
            }
          }
        }, {
          method: 'GET',
          path: '/logout',
          config: {
            auth: false,
            handler: function (request, reply) {
              request.auth.session.clear();
              reply.redirect(config.get('authentication.logout_uri'));
            }
          }
        }, {
          method: 'POST',
          path: '/_filtered_msearch',
          config: {
            payload: {
              parse: false
            },
            handler: function(request, reply) {
              var options = {
                method: 'POST',
                url: '/elasticsearch/_msearch',
                artifacts: true
              };
              if (request.auth.credentials.orgs.indexOf(config.get('authentication.cf_system_org')) !== -1) {
                options.payload = request.payload;
              } else {
                var modified_payload = [];
                var lines = request.payload.toString().split('\n');
                var num_lines = lines.length;
                for (var i = 0; i < num_lines - 1; i+=2) {
                  var indexes = lines[i];
                  var query = JSON.parse(lines[i+1]);
                  query.query.filtered.filter.bool.filter = [
                    {
                      "terms": {
                        "@source.space.id": request.auth.credentials.spaceIds
                      }
                    },{
                      "terms": {
                        "@source.org.id": request.auth.credentials.orgIds
                      }
                    }
                  ];
                  modified_payload.push(indexes);
                  modified_payload.push(JSON.stringify(query));
                }
                options.payload = new Buffer(modified_payload.join('\n') + '\n');
              }
              options.headers = request.headers;
              delete options.headers.host;
              delete options.headers['user-agent'];
              delete options.headers['accept-encoding'];
              options.headers['content-length'] = options.payload.length;
              server.inject(options, (resp) => {
                reply(resp.result || resp.payload)
                  .code(resp.statusCode)
                  .type(resp.headers['content-type'])
                  .passThrough(true);
              });
            }
          }
        }
      ]);

    }); // end: server.register

    // Redirect _msearch through our own route so we can modify the payload
    server.ext('onRequest', function (request, reply) {
      if (/elasticsearch\/_msearch/.test(request.path) && !request.auth.artifacts) {
        request.setUrl('/_filtered_msearch');
      }
      return reply.continue();

    }); // end server.ext('onRequest'


  }

  });
};
