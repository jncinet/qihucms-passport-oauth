<?php

use Illuminate\Routing\Router;

// 接口
Route::group([
    // 页面URL前缀
    'prefix' => 'passport-auth',
    // 控制器命名空间
    'namespace' => 'Qihucms\PassportAuth\Controllers',
    'middleware' => ['api'],
    'as' => 'api.'
], function (Router $router) {
    // 登录
    $router->post('login', 'AuthController@login')
        ->name('auth.login');
    // 登出
    $router->post('logout', 'AuthController@logout')
        ->middleware('auth:api')
        ->name('auth.logout');
    // 刷新TOKEN
    $router->post('refresh-token', 'AuthController@refresh_token')
        ->name('auth.refresh_token');
});