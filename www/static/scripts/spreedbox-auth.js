'use strict';
(function(root, factory) {
	if (typeof define === 'function' && define.amd) {
		define(['sha'], factory);
	} else {
		root.spreedboxAuth = factory(root.jsSHA);
	}
}(this, function(JsSHA) {
	var currentURL = location.protocol + '//' + location.host + location.pathname + location.search;
	var currentScript = document.currentScript || (function() {
		var scripts = document.getElementsByTagName('script');
		var script = scripts[scripts.length - 1];
		if (script.src.indexOf('spreedbox-auth.js') === -1) {
			return null;
		}
		return script;
	})();
	var baseScriptURL = (function() {
		while (true) {
			if (currentScript === null) {
				break;
			}

			var link = document.createElement('a');
			link.href = currentScript.src;
			var parts = link.pathname.split('/spreedbox-auth.js', 2);
			if (parts.length === 2) {
				return parts[0];
			}

			break;
		}

		return '/spreedbox-auth/api/v1/static/scripts';
	})();
	var baseAPIURL = baseScriptURL.split('/static/', 2)[0];

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

	function getCookie(name) {
		var value = '; ' + document.cookie;
		var parts = value.split('; ' + name + '=');
		if (parts.length === 2) {
			return parts.pop().split(';').shift();
		}
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
		var base64 = base64URL.replace(/-/g, '+').replace(/_/g, '/');
		return window.atob(base64);
	}

	function base64URLEncode(s) {
		var base64 = window.btoa(s);
		return base64.replace(/\+/g, '-').replace(/\//g, '_');
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
				throw 'access token hash validation failed: ' + tokenHash + ', ' + tokenHashCheck;
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
		authorize_url: baseAPIURL + '/authorize',
		early_expired_percent: 80
	};
	function authorize(opts) {
		var options = mergeOptions(opts, authorizeDefaultOptions);

		// Get and kill all hash data.
		var params = parseHash(true);

		// Check parameters.
		if (params.error) {
			// Have error -> abort and trigger error handler.
			clearCurrentAuth();
			getAndClearStoredState();
			getAndClearStoredNonce();

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
				var nonce = getAndClearStoredNonce();

				if (params.state !== state) {
					err = 'invalid state';
					break;
				}

				// Validate and decode tokens.
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
		if (authorizeCurrentID.id_token_raw) {
			query.id_token_hint = authorizeCurrentID.id_token_raw;
		}

		// Redirect to authorize end point.
		location.replace(options.authorize_url + '?' + encodeParams(query));
	}

	var authorizeCurrent = null;
	var authorizeCurrentID = {};
	var authorizeClearedListeners = [];

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
		if (auth && auth.id_token_raw) {
			authorizeCurrentID.id_token_raw = auth.id_token_raw;
			authorizeCurrentID.id_token = auth.id_token;
		}
		authorizeCurrent = auth;
	}

	function clearCurrentAuth() {
		if (hasCurrentAuth) {
			setCurrentAuth(null);
			var length = authorizeClearedListeners.length;
			for (var i = 0; i < length; i++) {
				authorizeClearedListeners[i]();
			}
		}
	}

	function clearCurrentAuthID() {
		delete authorizeCurrentID.id_token_raw;
		delete authorizeCurrentID.id_token;
	}

	function registerCurrentAuthClearedListener(f) {
		authorizeClearedListeners.push(f);
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
				var auth = data.auth;
				if (!isAuthExpired(auth)) {
					auth.expires_in = (auth.received_at + auth.expires_in * 1000 - (new Date().getTime())) / 1000;
					//console.log('compute new expires_in', auth.expires_in * 1000);
					if (auth.expires_in > 10) {
						setCurrentAuth(auth);
					}
				}
				break;
		}
		return getCurrentAuth();
	}

	function isAuthExpired(auth) {
		var now = new Date().getTime();
		var grace = auth.expires_in * 1000 / 100 * authorizeDefaultOptions.early_expired_percent;
		if (auth.received_at + grace < now) {
			//console.log('auth expired', grace, now-auth.received_at, now, auth.received_at);
			return true;
		}

		return false;
	}

	function validateSessionState(clientID, origin, browserState) {
		// Validate session state - see http://openid.net/specs/openid-connect-session-1_0.html#OPiframe
		// for details and base specification.

		var auth = getCurrentAuth();
		if (!auth) {
			return false;
		}

		if (!auth.session_state) {
			// No session state in auth is a success (means no session).
			return true;
		}

		var salt = auth.session_state.split('.')[1];
		var shaObj = new JsSHA('SHA-256', 'TEXT');
		shaObj.update(clientID);
		shaObj.update(' ');
		shaObj.update(origin);
		shaObj.update(' ');
		shaObj.update(browserState);
		shaObj.update(' ');
		shaObj.update(salt);
		var sessionState = shaObj.getHash('B64') + '.' + salt;

		return sessionState == auth.session_state;
	}

	// Revocate app.
	var revocateDefaultOptions = {
		token_type_hint: 'access_token',
		revocate_url: baseAPIURL + '/revocate'
	};
	function revocate(opts) {
		var options = mergeOptions(opts, revocateDefaultOptions);

		var auth = getCurrentAuth();
		if (!auth) {
			if (options.onSuccess) {
				options.onSuccess('no auth');
			}
			return;
		}

		var token;
		var tokenTypeHint = options.token_type_hint;
		switch (tokenTypeHint) {
			case 'id_token':
				token = auth.id_token_raw;
				break;
			case '':
				tokenTypeHint = 'access_token';
				// fallthrough
			case 'access_token':
				token = auth.access_token_raw;
				break;
			default:
				throw 'unsupported token type';
		}

		if (!token) {
			throw 'no token';
		}

		var params = {
			token: token,
			token_type_hint: tokenTypeHint
		};

		var r = new XMLHttpRequest();
		r.open('POST', options.revocate_url, true);
		r.setRequestHeader('Authorization', auth.token_type + ' ' + token);
		r.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
		r.onreadystatechange = function() {
			if (r.readyState === 4) { // done
				if (r.status === 200) { // ok
					if (options.onSuccess) {
						options.onSuccess(r.responseText);
					}
				} else {
					if (options.onError) {
						options.onError(r.status, r.responseText);
					}
				}
			}
		};
		r.send(encodeParams(params));
	};

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
				if (query.debug) {
					console.info('spreedbox-auth', params);
				}
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
					case 'session_state':
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

		return new Redirector(options);
	}

	// Refresher app.
	var refresherDefaultOptions = {
		refresher_url: baseScriptURL + '/../refresher.html',
		cache: true,
		load_error_retry_seconds: 10,
		null_auth_refresh_seconds: 60,
		early_refresh_percent: 70,
		browser_state_cookie_name: 'oc_spreedbox',
		browser_state_check_seconds: 120
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
			var currentAuth = getCurrentAuth();
			var currentState = null;
			this.frame.addEventListener('load', function() {
				if (!this.contentWindow.run && settings.load_error_retry_seconds > 0) {
					refresher.timer = window.setTimeout(function() {
						refresher.frame.setAttribute('src', settings.refresher_url);
					}, settings.load_error_retry_seconds * 1000);
					return;
				}

				this.contentWindow.run(currentAuth, function(auth, error, cb) {
					refresher.ready = true;
					window.clearTimeout(refresher.timer);
					var refreshSeconds = settings.null_auth_refresh_seconds;
					if (error === null) {
						if (auth) {
							setCurrentAuth(auth);
							refreshSeconds = (auth.expires_in || 3600) / 100 * settings.early_refresh_percent;
							if (refreshSeconds > 3600) {
								refreshSeconds = 3600;
							}
							//console.info('refresh in ', refreshSeconds, ' seconds', auth.expires_in);
							if (currentState !== auth.state) {
								currentState = auth.state;
								trigger(refresher, 'auth', auth, null);
							}
						} else {
							clearCurrentAuth();
							trigger(refresher, 'auth', null, null);
						}
					} else {
						trigger(refresher, 'auth', getCurrentAuth(), error);
					}
					// Schedule next run.
					if (refreshSeconds > 0) {
						refresher.timer = window.setTimeout(function() {
							refresher.refresh();
						}, refreshSeconds * 1000);
					}
					// Cache support.
					if (settings.cache) {
						cacheCurrentAuth();
					}
					// Callback.
					if (cb) {
						cb(auth, error);
					}
				}, settings, null);
				currentAuth = null;
			});

			// Register our clear function,
			registerCurrentAuthClearedListener(function() {
				refresher.clear();
			});

			// Always trigger auth after creation.
			window.setTimeout(function() {
				if (currentAuth) {
					currentState = currentAuth.state;
				}
				trigger(refresher, 'auth', currentAuth, null);
				refresher.frame.setAttribute('src', settings.refresher_url);
			}, 0);
		}

		Refresher.prototype.clear = function() {
			window.clearTimeout(this.timer);
			if (hasCurrentAuth()) {
				clearCurrentAuth();
			}
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

	// Logout app.
	function LogoutApp(opts) {
		var options = mergeOptions(opts, {});
		options.onSuccess = function() {
			clearCurrentAuth();
			cacheCurrentAuth();
			clearCurrentAuthID();
			if (opts && opts.onSuccess) {
				opts.onSuccess.apply(this, arguments);
			}
		};

		function Logout(settings) {
			revocate(settings);
		}

		return new Logout(options);
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
	spreedboxAuth.revocate = revocate;
	spreedboxAuth.revocate.defaultOptions = revocateDefaultOptions;
	spreedboxAuth.get = getCurrentAuth;
	spreedboxAuth.session = {
		validate: validateSessionState
	};
	spreedboxAuth.app = {
		redirector: RedirectorApp,
		refresher: RefresherApp,
		handler: HandlerApp,
		logout: LogoutApp
	};
	spreedboxAuth.run = {
		authorize: function() {
			var handler = RedirectorApp();
			window.redirector = handler;
		},
		refresh: function() {
			// Create Handler app instance without prompt.
			var handler = HandlerApp({prompt: 'none'});
			// Bind global run function (is called by parent).
			window.run = function(currentAuth, handleFunc, options, cb) {
				handler.setup(handleFunc, options);
				if (currentAuth) {
					setCurrentAuth(currentAuth);
					window.setTimeout(function() {
						handleFunc(currentAuth, null, cb);
					}, 0);
					return;
				}
				handler.authorize(cb);
				if (options && options.browser_state_check_seconds) {
					window.setInterval(function() {
						window.validate(options.browser_state_cookie_name, cb);
					}, options.browser_state_check_seconds * 1000);
				}
			};
			// Bind global authorize function (is called by parent).
			window.authorize = function(cb) {
				handler.authorize(cb);
			};
			// Add a validate function for session state validation.
			var origin = location.protocol + '//' + location.host;
			window.validate = function(cookieName, cb) {
				if (cookieName && hasCurrentAuth()) {
					var browserState = getCookie(cookieName);
					if (!browserState) {
						browserState = 'provider_without_state';
					}
					var valid = validateSessionState(currentURL, origin, browserState);
					if (!valid) {
						window.setTimeout(function() {
							handler.authorize(cb);
						}, 0);
					}
				}
			};
		}
	};
	RedirectorApp.defaultOptions = redirectorDefaultOptions;
	RefresherApp.defaultOptions = refresherDefaultOptions;
	HandlerApp.defaultOptions = handlerDefaultOptions;

	// Auto run support.
	(function() {
		var head = document.getElementsByTagName('head')[0];
		var run = head.getAttribute('spreedbox-auth-run');
		if (run) {
			window.addEventListener('load', function spreedboxAuthAutoRun() {
				spreedboxAuth.run[run]();
			}, true);
		}
	})();

	return spreedboxAuth;
}));
