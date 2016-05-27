'use strict';
(function(root, factory) {
	if (typeof define === 'function' && define.amd) {
		define(['sha'], factory);
	} else {
		root.spreedboxAuth = factory(root.jsSHA);
	}
}(this, function(JsSHA) {
	var currentURL = location.protocol + '//' + location.host + location.pathname + location.search;

	function encodeParams(params) {
		var result = [];
		var p;
		for (p in params) {
			if (params.hasOwnProperty(p)) {
				result.push(encodeURIComponent(p) + '=' + encodeURIComponent(params[p]));
			}
		}

		return result.join('&');
	}

	function decodeParams(s) {
		var regex = /([^&=]+)=([^&]*)/g;
		var result = {};
		var m;
		while (m = regex.exec(s)) {
			result[decodeURIComponent(m[1])] = decodeURIComponent(m[2]);
		}

		return result;
	}

	function getRandomString(length) {
		if (!length || length < 0) {
			length = 12;
		}
		var data = new Uint32Array(32);
		window.crypto.getRandomValues(data);
		var shaObj = new JsSHA('SHA-256', 'ARRAYBUFFER');
		shaObj.update(data);

		return shaObj.getHash('HEX').substr(0, length);
	}

	function createNonce() {
		var data = new Uint32Array(32);
		window.crypto.getRandomValues(data);
		var shaObj = new JsSHA('SHA-256', 'ARRAYBUFFER');
		shaObj.update(data);
		var nonce = shaObj.getHash('HEX');
		sessionStorage.setItem('spreedbox-auth-nonce', nonce);

		return nonce;
	}

	function getAndClearStoredNonce() {
		var nonce = sessionStorage.getItem('spreedbox-auth-nonce');
		sessionStorage.removeItem('spreedbox-auth-nonce');

		return nonce;
	}

	function createState() {
		var state = getRandomString(12);
		sessionStorage.setItem('spreedbox-auth-state', state);

		return state;
	}

	function getAndClearStoredState() {
		var state = sessionStorage.getItem('spreedbox-auth-state');
		sessionStorage.removeItem('spreedbox-auth-state');

		return state;
	}

	function base64URLDecode(base64URL) {
		var base64 = base64URL.replace('-', '+').replace('_', '/');
		return window.atob(base64);
	}

	function base64URLEncode(s) {
		var base64 = window.btoa(s);
		return base64.replace('+', '-').replace('/', '_');
	}

	function base64URLDecodeJSON(base64URL) {
		return JSON.parse(base64URLDecode(base64URL));
	}

	function parseAndValidateJWT(token, nonce, tokenHash) {
		// NOTE(longsleep): We do not validate the JWT signature client side.
		var parts = token.split('.', 3);
		var header = base64URLDecodeJSON(parts[0]);
		var data = base64URLDecodeJSON(parts[1]);

		// Validate.
		if (data.iss !== 'https://self-issued.me') {
			throw 'iss validation failed';
		}
		if (data.aud !== currentURL) {
			throw 'aud validation failed';
		}
		if (data.nonce !== nonce) {
			throw 'nonce validation failed';
		}
		var now = (new Date().getTime() / 1000);
		if (data.exp <= now) {
			throw 'exp validation failed';
		}
		var away = Math.abs(now - data.iat);
		if (away >= 120) {
			throw 'iat validation failed';
		}
		if (tokenHash) {
			if (header.typ !== 'JWT') {
				throw 'header typ unsupported: ' + header.typ;
			}

			// Validate left-most hash (http://openid.net/specs/openid-connect-core-1_0.html#CodeValidation).
			var mode;
			switch (header.alg) {
				case 'RS256':
					mode = 'SHA-256';
					break;
				case 'RS384':
					mode = 'SHA-384';
					break;
				case 'RS512':
					mode = 'SHA-512';
					break;
			}
			if (!mode) {
				throw 'header alg unsupported: ' + header.alg;
			}
			var shaObj = new JsSHA(mode, 'TEXT');
			shaObj.update(token);
			var tokenHashCheck = base64URLEncode(shaObj.getHash('BYTES').substr(0, 16));
			if (tokenHash !== tokenHashCheck) {
				throw 'access token hash validation failed';
			}
		}

		// Ok.
		return data;
	}

	function parseHash(kill) {
		var params = decodeParams(location.hash.substring(1));
		if (kill) {
			history.replaceState('', document.title, currentURL);
		}

		return params;
	}

	// Our main app.
	var defaultOptions = {
		response_type: 'id_token token',
		scope: 'openid',
		authorize_url: '/spreedbox-auth/authorize'
	};
	var currentAuth = null;
	function authorize(opts) {
		var options = {};
		var key;
		for (key in defaultOptions) {
			if (defaultOptions.hasOwnProperty(key)) {
				options[key] = defaultOptions[key];
			}
		}
		if (opts) {
			for (key in opts) {
				if (opts.hasOwnProperty(key)) {
					options[key] = opts[key];
				}
			}
		}

		// Get and kill all hash data.
		var params = parseHash(true);

		// Check parameters.
		if (params.error) {
			// Have error -> abort and trigger error handler.
			if (options.onError) {
				options.onError(params);
			} else {
				throw 'spreedbox-auth failed: ' + params.error + ' - ' + params.error_description;
			}

			return;
		} else if (params.state) {
			// Have state, means it is a response, check everything.
			var state = getAndClearStoredState();
			var err;
			while (true) {

				if (params.state !== state) {
					err = 'invalid state';
					break;
				}

				// Validate and decode tokens.
				var nonce = getAndClearStoredNonce();
				var atHash = null;
				if (params.id_token) {
					params.id_token_raw = params.id_token;
					try {
						params.id_token = parseAndValidateJWT(params.id_token_raw, nonce);
					} catch (e) {
						err = e;
						break;
					}
					if (params.id_token) {
						atHash = params.id_token.at_hash;
					} else {
						// Invalid ID token automatically mark access token as invalid as well.
						params.access_token_raw = params.access_token;
						params.access_token = null;
					}
				}
				if (params.access_token) {
					params.access_token_raw = params.access_token;
					try {
						params.access_token = parseAndValidateJWT(params.access_token_raw, nonce, atHash);
					} catch (e) {
						err = e;
						break;
					}
				}

				break;
			}

			if (err) {
				if (options.onError) {
					options.onError({error: err});
					return;
				}
				throw 'spreedbox-auth error: ' + err;
			}

			// Set current auth.
			currentAuth = params;
			if (options.onSuccess) {
				// Trigger success handler with a copy.
				options.onSuccess(getCurrentAuth());
			}

			return;
		}
		// else we try to authorize new.

		// Build API query parameters.
		var query = {
			response_type: options.response_type,
			redirect_url: currentURL,
			nonce: createNonce(),
			state: createState(),
			scope: options.scope
		};
		if (params.authprovided) {
			// Force prompt to none, if authprovided is set.
			query.prompt = 'none';
		} else {
			if (options.hasOwnProperty('prompt')) {
				query.prompt = options.prompt;
			}
		}

		// Redirect to authorize end point.
		location.replace(options.authorize_url + '?' + encodeParams(query));
	}

	function getCurrentAuth() {
		if (currentAuth === null) {
			return null;
		}
		return JSON.parse(JSON.stringify(currentAuth));
	}

	// Simple redirector app.
	function redirector(defaultTarget) {
		var query = decodeParams(location.search.substring(1));

		function handler(params) {
			var target = query.target;
			if (!target) {
				target = defaultTarget;
			}

			if (!target) {
				return;
			}
			var link = document.createElement('a');
			link.href = target;
			link.hash = encodeParams(params);
			if (link.protocol !== 'https:' || link.host !== location.host) {
				throw 'invalid or insecure target';
			}
			var url = link.protocol + '//' + link.host + link.pathname + link.search + link.hash;

			location.replace(url);
		}

		var options = {
			onSuccess: function(values) {
				var params = {};
				for (var key in values) {
					if (values.hasOwnProperty(key)) {
						switch (key) {
						case 'access_token_raw':
						case 'id_token_raw':
							params[key.substr(0, key.length - 4)] = values[key];
							break;
						case 'code':
						case 'token_type':
						case 'expires_in':
						case 'state':
							params[key] = values[key];
						default:
							break;
						}
					}
				}
				handler(params);
			},
			onError: function(error) {
				var params = {
					error: error.error || 'unknown error',
					error_description: error.error_description || ''
				};
				handler(params);
			}
		};

		if (query.hasOwnProperty('response_type')) {
			options.response_type = query.response_type;
		}
		if (query.hasOwnProperty('scope')) {
			options.scope = query.scope;
		}
		if (query.hasOwnProperty('prompt')) {
			options.prompt = query.prompt;
		}

		// Authorize.
		authorize(options);
	}

	// Expose public API.
	var spreedboxAuth = function spreedboxAuth(options) {
		return authorize(options);
	};
	spreedboxAuth.defaultOptions = defaultOptions;
	spreedboxAuth.decodeParams = decodeParams;
	spreedboxAuth.encodeParams = encodeParams;
	spreedboxAuth.parseHash = parseHash;
	spreedboxAuth.authorize = authorize;
	spreedboxAuth.get = getCurrentAuth;
	spreedboxAuth.app = {
		redirector: redirector
	};

	return spreedboxAuth;
}));
