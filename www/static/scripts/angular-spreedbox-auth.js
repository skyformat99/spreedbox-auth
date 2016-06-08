'use strict';

angular.module('ngSpreedboxAuth', [])
	.provider('spreedboxAuth', [function() {
		var first = true;
		var currentAuth = null;
		var currentAuthError = null;
		var currentRefresher = null;

		var provider = this;
		// Provider function, can be used in routes as resolvable.
		this.authRequired = ['$q', '$location', '$window', '$rootScope', function($q, $location, $window, $rootScope) {
			if (currentAuth && currentRefresher) {
				currentRefresher.start();
				return currentAuth;
			}

			provider.deferred = $q.defer();
			if (!currentRefresher) {
				currentRefresher = $window.spreedboxAuth.app.refresher();
				currentRefresher.onauth = function(auth, error) {
					console.log('xxx refresher onauth', auth, error, provider.deferred);
					var currentAuthBackup = currentAuth;
					currentAuthError = error;
					if (auth) {
						currentAuth = auth;
						if (provider.deferred !== null) {
							provider.deferred.resolve(auth);
							provider.deferred = null;
						}
					} else {
						if (error) {
							$rootScope.$broadcast('auth-error', error, auth);
						} else {
							// No auth and no error, must be a clear / logout.
							currentAuth = null;
						}
					}
					if (currentAuth !== currentAuthBackup || first || error) {
						$rootScope.$broadcast('auth-changed', currentAuth, error);
					}
					first = false;
				};

				// Expose a refresher reference, for whatever API voodoo.
				provider.refresher = this;
			} else {
				currentRefresher.start(true);
			}

			return provider.deferred.promise;
		}];

		// Factory.
		this.$get = ['$rootScope', '$window', function spreedboxAuthFactory($rootScope, $window) {
			function SpreedboxAuth() {
			}

			SpreedboxAuth.prototype.get = function() {
				return currentAuth;
			};

			SpreedboxAuth.prototype.getError = function() {
				return currentAuthError;
			};

			SpreedboxAuth.prototype.hasValidAuth = function() {
				if (!currentAuthError && currentAuth && currentAuth.id_token.sub) {
					return true;
				}

				return false;
			};

			SpreedboxAuth.prototype.clear = function() {
				if (currentRefresher) {
					currentRefresher.clear();
				}
				first = true;
			};

			SpreedboxAuth.prototype.logout = function(options) {
				first = true;
				$window.spreedboxAuth.app.logout(options);
			};

			SpreedboxAuth.prototype.authorize = function(options) {
				$window.spreedboxAuth.authorize(options);
			};

			SpreedboxAuth.prototype.addAccessTokenAuthorizeHeader = function(headers) {
				if (currentAuth && currentAuth.access_token_raw) {
					headers.Authorization = currentAuth.token_type + ' ' + currentAuth.access_token_raw;
				}

				return headers;
			};

			SpreedboxAuth.prototype.addAccessTokenQueryParam = function(url) {
				if (currentAuth && currentAuth.access_token_raw) {
					var param;
					if (url.indexOf('?') > -1) {
						param = '&';
					} else {
						param = '?';
					}
					url = url + param + 'access_token=' + currentAuth.access_token_raw;
				}

				return url;
			};

			return new SpreedboxAuth();
		}];
	}]);
