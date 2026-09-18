<?php

/**
 * This file contains the routes needed for SPIDAuth Package.
 *
 * @license BSD-3-clause
 */
use Illuminate\Support\Facades\Route;
use Italia\SPIDAuth\SPIDAuth;

Route::group([
    'prefix' => config('spid-auth.routes_prefix'),
    'middleware' => config('spid-auth.middleware_group'),
], function () {
    Route::get('login', [SPIDAuth::class, 'login'])->name('spid-auth_login');
    Route::post('login', [SPIDAuth::class, 'doLogin'])->name('spid-auth_do-login');
    Route::match(['get', 'post'], 'logout', [SPIDAuth::class, 'logout'])->name('spid-auth_logout');
    Route::post('acs', [SPIDAuth::class, 'acs'])->name('spid-auth_acs');
    Route::get('metadata', [SPIDAuth::class, 'metadata'])->name('spid-auth_metadata');
    Route::get('providers', [SPIDAuth::class, 'providers'])->name('spid-auth_providers');
}
);
