var gulp = require('gulp');
var gulpUtil = require('gulp-util');
var uglify = require('gulp-uglify');
var minifyInline = require('gulp-minify-inline');
var jscs = require('gulp-jscs');

gulp.task('scripts', function() {
	gulp.src([
		'static/scripts/*.js'])
		.pipe(uglify().on('error', gulpUtil.log))
		.pipe(gulp.dest('build/static/scripts/'));

	gulp.src([
		'static/lib/*.js'])
		.pipe(gulp.dest('build/static/lib/'));
});

gulp.task('apps', function() {
	gulp.src([
		'static/*.html'])
		.pipe(minifyInline().on('error', gulpUtil.log))
		.pipe(gulp.dest('build/static/'));
});

gulp.task('jscs', function() {
	return gulp.src([
		'static/scripts/*.js'])
		.pipe(jscs())
		.pipe(jscs.reporter())
		.pipe(jscs.reporter('fail'));
})

// The default task (called when you run `gulp`)
gulp.task('default', ['scripts', 'apps']);