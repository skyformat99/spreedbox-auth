console.log("spreedox-auth loading ...");

(function(root, factory) {
	if (typeof define === 'function' && define.amd) {
		define(['jsSHA'], factory);
	} else {
		root.spreedboxAuth = factory(root.jsSHA);
	}
}(this, function(jsSHA) {
	var authorizeURL = '/spreedbox-auth/authorize';
	var currentURL = location.protocol + '//' + location.host + location.pathname + location.search;

	function encodeParams(params) {
		var result = [];
		for (var p in params) {
			if (params.hasOwnProperty(p)) {
				result.push(encodeURIComponent(p) + '=' + encodeURIComponent(params[p]));
			}
		}

		return result.join('&');
	};

	function decodeParams(s) {
		var regex = /([^&=]+)=([^&]*)/g;
		var result = {};
		var m;
		while (m = regex.exec(s)) {
			result[decodeURIComponent(m[1])] = decodeURIComponent(m[2])
		}

		return result;
	};

	function getRandomString(length) {
		var dict = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW0123456789"
		var size = dict.length;

		if (!length || length < 0) {
			length = 12;
		}

		var array = new Uint8Array(length)
		window.crypto.getRandomValues(array)
		var result = [];
		for (var i=0; i<length; i++) {
			result[i]=dict[array[i]%size];
		}

		return result.join('');
	};

	function createNonce() {
		var data = new Uint32Array(32);
		window.crypto.getRandomValues(data);
		var shaObj = new jsSHA('SHA-256', 'ARRAYBUFFER');
		shaObj.update(data);
		var nonce = shaObj.getHash('HEX')
		sessionStorage.setItem('spreedbox-auth-nonce', nonce);
		console.log('nonce', nonce);

		return nonce;
	};

	function getAndClearStoredNonce() {
		var nonce = sessionStorage.getItem('spreedbox-auth-nonce');
		sessionStorage.removeItem('spreedbox-auth-nonce');

		return nonce;
	};

	function createState() {
		var state = getRandomString(12);
		sessionStorage.setItem('spreedbox-auth-state', state);

		return state;
	};

	function getAndClearStoredState() {
		var state = sessionStorage.getItem('spreedbox-auth-state');
		sessionStorage.removeItem('spreedbox-auth-state');

		return state;
	};

	function base64URLDecode(base64URL) {
		var base64 = base64URL.replace('-', '+').replace('_', '/');
		return window.atob(base64);
	};

	function base64URLEncode(s) {
		var base64 = window.btoa(s);
		return base64.replace('+', '-').replace('/', '_');
	};

	function base64URLDecodeJSON(base64URL) {
		return JSON.parse(base64URLDecode(base64URL));
	};

	function parseAndValidateJWT(token, nonce, token_hash) {
		// NOTE(longsleep): We do not validate the JWT signature client side.
		var parts = token.split('.', 3)
		var header = base64URLDecodeJSON(parts[0]);
		var data = base64URLDecodeJSON(parts[1]);

		// Validate.
		while(true) {
			if (data.iss !== 'https://self-issued.me') {
				console.warn('iss validation failed');
				break;
			}
			if (data.aud !== currentURL) {
				console.warn('aud validation failed');
				break;
			}
			if (data.nonce !== nonce) {
				console.warn('nonce validation failed');
				break;
			}
			var now = (new Date().getTime() / 1000);
			if (data.exp <= now) {
				console.warn('exp validation failed');
				break;
			}
			var away = Math.abs(now - data.iat);
			if (away >= 120) {
				console.warn('iat validation failed');
				break;
			}
			if (token_hash) {
				if (header.typ !== 'JWT') {
					console.warn('header typ unsupported', header.typ);
					break;
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
					console.warn('header alg unsupported', header.alg);
					break;
				}
				var shaObj = new jsSHA(mode, 'TEXT');
				shaObj.update(token);
				var token_hash_check = base64URLEncode(shaObj.getHash('BYTES').substr(0, 16));
				if (token_hash !== token_hash_check) {
					console.warn('access token hash validation failed');
					break;
				}
			}

			// Ok.
			return data;
		}

		return null;
	};

	function spreedboxAuth(successCb, errorCb) {
		console.log("spreedbox-auth run ...");
		var params = decodeParams(location.hash.substring(1));

		// Remove all hash content.
		history.replaceState('', document.title, currentURL);

		// Check parameters.
		if (params.error) {
			console.error('spreedbox-auth failed', params.error, params.error_description);
			if (errorCb) {
				errorCb(params);
			}
			return;
		} else if (params.state) {
			var state = getAndClearStoredState();
			if (params.state !== state) {
				console.error('spreedbox-auth invalid state');
				if (errorCb) {
					errorCb(null);
				}
				return;
			}

			// Validate and decode tokens.
			var nonce = getAndClearStoredNonce();
			var at_hash = null;
			if (params.id_token) {
				params.id_token_raw = params.id_token;
				params.id_token = parseAndValidateJWT(params.id_token_raw, nonce);
				if (params.id_token) {
					at_hash = params.id_token.at_hash;
				} else {
					// Invalid ID token automatically mark access token as invalid as well.
					params.access_token_raw = params.access_token;
					params.access_token = null;
				}
			}
			if (params.access_token) {
				params.access_token_raw = params.access_token;
				params.access_token = parseAndValidateJWT(params.access_token_raw, nonce, at_hash);
			}

			if (successCb) {
				successCb(params);
			}
			return;
		}

		// Redirect to authorize end point.
		var query = encodeParams({
			response_type: 'id_token token',
			redirect_url: currentURL,
			nonce: createNonce(),
			state: createState(),
			scope: 'openid'
		});
		location.replace(authorizeURL + '?' + query);
	};

	return spreedboxAuth;
}));
