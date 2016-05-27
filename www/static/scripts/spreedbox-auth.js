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

	function mergeOptions(opts, defaultOpts) {
		var options = {};
		var key;
		for (key in defaultOpts) {
			if (defaultOpts.hasOwnProperty(key)) {
				options[key] = defaultOpts[key];
			}
		}
		if (opts) {
			for (key in opts) {
				if (opts.hasOwnProperty(key)) {
					options[key] = opts[key];
				}
			}
		}

		return options;
	}

	// Our main app.
	var authorizeDefaultOptions = {
		response_type: 'id_token token',
		scope: 'openid',
		authorize_url: '/spreedbox-auth/authorize'
	};
	function authorize(opts) {
		var options = mergeOptions(opts, authorizeDefaultOptions);

		// Get and kill all hash data.
		var params = parseHash(true);

		// Check parameters.
		if (params.error) {
			// Have error -> abort and trigger error handler.
			clearCurrentAuth();
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
				if (params.expires_in) {
					try {
						params.expires_in = parseInt(params.expires_in, 10);
					} catch (e) {
						err = e;
						break;
					}
				}

				break;
			}

			if (err) {
				clearCurrentAuth();
				if (options.onError) {
					options.onError({error: err});
					return;
				}
				throw 'spreedbox-auth error: ' + err;
			}

			// Set current auth.
			setCurrentAuth(params);
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

	var authorizeCurrent = null;

	function hasCurrentAuth() {
		return authorizeCurrent !== null;
	}

	function getCurrentAuth() {
		if (authorizeCurrent === null) {
			return null;
		}
		return JSON.parse(JSON.stringify(authorizeCurrent));
	}

	function setCurrentAuth(auth) {
		if (auth && !auth.hasOwnProperty('received_at')) {
			auth.received_at = new Date().getTime();
		}
		authorizeCurrent = auth;
	}

	function clearCurrentAuth() {
		setCurrentAuth(null);
	}

	function cacheCurrentAuth() {
		if (!authorizeCurrent) {
			sessionStorage.removeItem('spreedbox-auth-cached');
			return;
		}
		var data = {
			v: 1,
			auth: authorizeCurrent
		};
		sessionStorage.setItem('spreedbox-auth-cached', JSON.stringify(data));
	}

	function loadCurrentAuthFromCache() {
		var s = sessionStorage.getItem('spreedbox-auth-cached');
		if (!s) {
			return null;
		}
		var data = JSON.parse(s);
		switch (data.v) {
			case 1:
				if (!isAuthExpired(data.auth)) {
					setCurrentAuth(data.auth);
				}
				break;
		}
		return getCurrentAuth();
	}

	function isAuthExpired(auth) {
		var now = new Date().getTime();
		if (auth.received_at + (auth.expires_in * 1000 / 100 * 80) < now) {
			return true;
		}

		return false;
	}

	// Simple redirector app.
	var redirectorDefaultOptions = {};
	function RedirectorApp(opts) {
		var options = mergeOptions(opts, redirectorDefaultOptions);
		var query = decodeParams(location.search.substring(1));

		function Redirector(settings) {
			// Authorize.
			authorize(settings);
		}

		function handler(params) {
			var target = query.target;
			if (!target) {
				target = options.default_target;
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

		options.onSuccess = function(values) {
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
		};

		options.onError = function(error) {
			var params = {
				error: error.error || 'unknown error',
				error_description: error.error_description || ''
			};
			handler(params);
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

		redirectorCurrent = new Redirector(options);
		return redirectorCurrent;
	}

	// Refresher app.
	var refresherDefaultOptions = {
		refresher_url: '/spreedbox-auth/static/refresher.html',
		cache: true
	};
	function RefresherApp(opts) {
		var options = mergeOptions(opts, refresherDefaultOptions);

		function trigger(refresher, name, auth, error) {
			var f = refresher['on' + name];
			if (f) {
				f(auth, error);
			}
		}

		function Refresher(settings) {
			this.ready = false;
			this.timer = null;
			var refresher = this;

			if (settings.cache && !hasCurrentAuth()) {
				// Load from cache.
				loadCurrentAuthFromCache();
			}

			this.frame = document.createElement('iframe');
			this.frame.className = 'spreedbox-auth-refresher';
			this.frame.style.display = 'none';
			document.body.appendChild(this.frame);
			this.frame.addEventListener('load', function() {
				this.contentWindow.run(getCurrentAuth(), function(auth, error, cb) {
					refresher.ready = true;
					window.clearTimeout(refresher.timer);
					if (auth) {
						setCurrentAuth(auth);
						var refreshSeconds = (auth.expires_in || 3600) / 100 * 70;
						if (refreshSeconds > 3600) {
							refreshSeconds = 3600;
						}
						refresher.timer = window.setTimeout(function() {
							refresher.refresh();
						}, refreshSeconds * 1000);
						trigger(refresher, 'auth', auth, error);
					} else {
						clearCurrentAuth();
						trigger(refresher, 'auth', null, error);
					}
					if (settings.cache) {
						cacheCurrentAuth();
					}
					if (cb) {
						cb(auth, error);
					}
				}, null, null);
			});

			// Always trigger auth after creation.
			window.setTimeout(function() {
				trigger(refresher, 'auth', getCurrentAuth(), null);
				refresher.frame.setAttribute('src', settings.refresher_url);
			}, 0);
		}

		Refresher.prototype.clear = function() {
			window.clearTimeout(this.timer);
			clearCurrentAuth();
			trigger(this, 'auth', null, null);
		};

		Refresher.prototype.refresh = function(cb) {
			if (this.ready) {
				this.ready = false;
				this.frame.contentWindow.authorize(cb);
			}
		};

		Refresher.prototype.with = function(cb) {
			var auth = getCurrentAuth();
			if (!cb) {
				return auth;
			}

			if (auth && !isAuthExpired(auth)) {
				window.setTimeout(function() {
					cb(auth, null);
				}, 0);
			} else {
				var that = this;
				window.setTimeout(function() {
					that.refresh(cb);
				}, 0);
			}
		};

		// Refresher API.
		// - refresher.onauth(auth, error) (register as function)
		// - refresher.clear()
		// - refresher.refresh()
		// - refresher.with(cb)

		return new Refresher(options);
	}

	// Handler app.
	var handlerDefaultOptions = {};
	function HandlerApp(opts) {
		var options = mergeOptions(opts, handlerDefaultOptions);

		function Handler(settings) {
			this.settings = settings;
			this.handleFunc = null;
			this.options = null;
		}

		Handler.prototype.setup = function(handleFunc, opts) {
			this.handleFunc = handleFunc;

			var options = mergeOptions(opts, this.settings);
			this.options = options;
		};

		Handler.prototype.authorize = function(cb) {
			if (this.handleFunc === null) {
				throw 'handler is not set up';
			}

			var handleFunc = this.handleFunc;
			var options = mergeOptions(null, this.options);
			options.onSuccess = function onSuccess(values) {
				handleFunc(values, null, cb);
			};
			options.onError = function onError(error) {
				handleFunc(null, error, cb);
			};

			authorize(options);
		};

		return new Handler(options);
	}

	// Expose public API.
	var spreedboxAuth = function spreedboxAuth(options) {
		return authorize(options);
	};
	spreedboxAuth.defaultOptions = authorizeDefaultOptions;
	spreedboxAuth.decodeParams = decodeParams;
	spreedboxAuth.encodeParams = encodeParams;
	spreedboxAuth.parseHash = parseHash;
	spreedboxAuth.authorize = authorize;
	spreedboxAuth.authorize.defaultOptions = authorizeDefaultOptions;
	spreedboxAuth.get = getCurrentAuth;
	spreedboxAuth.app = {
		redirector: RedirectorApp,
		refresher: RefresherApp,
		handler: HandlerApp
	};
	RedirectorApp.defaultOptions = redirectorDefaultOptions;
	RefresherApp.defaultOptions = refresherDefaultOptions;
	HandlerApp.defaultOptions = handlerDefaultOptions;

	return spreedboxAuth;
}));
