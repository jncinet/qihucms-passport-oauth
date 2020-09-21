<?php

namespace Qihucms\PassportAuth\Controllers;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Qihucms\PassportAuth\TokenProxy;
use Illuminate\Foundation\Auth\AuthenticatesUsers;

class AuthController extends Controller
{
    use AuthenticatesUsers;

    /**
     * 登录系统
     *
     * @param \Illuminate\Http\Request $request
     * @return mixed
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function login(Request $request)
    {
        // 验证格式
        $this->validateLogin($request);

        // 多次登录失败阻断
        if (method_exists($this, 'hasTooManyLoginAttempts') &&
            $this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);

            // 错误提示
            $this->sendLockoutResponse($request);
            return null;
        }

        // 账号密码是否通过验证
        if ($this->attemptLogin($request)) {
            return $this->sendLoginResponse($request);
        }

        // 登记登录失败次数
        $this->incrementLoginAttempts($request);

        // 错误提示
        return $this->sendFailedLoginResponse($request);
    }

    // 刷新登录
    public function refresh_token(Request $request)
    {
        $refreshToken = $request->input('refresh_token');
        return (new TokenProxy())->proxy(
            'refresh_token',
            [
                'refresh_token' => $refreshToken,
                'scope' => ''
            ]
        );
    }

    /**
     * 多字段账户认证
     *
     * @param \Illuminate\Http\Request $request
     * @return bool
     */
    protected function attemptLogin(Request $request)
    {
        return collect(['username', 'email', 'mobile'])->contains(function ($value) use ($request) {
            $account = $request->input($this->username());
            $password = $request->input('password');
            return $this->guard()->attempt(
                [
                    $value => $account,
                    'password' => $password
                ],
                $request->filled('remember')
            );
        });
    }

    /**
     * 重写表单验证项
     *
     * @param \Illuminate\Http\Request $request
     * @return void
     */
    protected function validateLogin(Request $request)
    {
        $request->validate(
            [
                $this->username() => 'required|string|min:5|max:66',
                'password' => 'required|string'
            ],
            [
                'required' => ':attribute必须填写',
                'string' => ':attribute必须是字符串',
                'min' => ':attribute最少:min位',
                'max' => ':attribute最少:max位'
            ],
            [
                $this->username() => '登录账号',
                'password' => '登录密码'
            ]
        );
    }

    /**
     * 去掉了原来的session操作
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     */
    protected function sendLoginResponse(Request $request)
    {
        $this->clearLoginAttempts($request);
        return $this->authenticated($request, $this->guard()->user());
    }

    /**
     * 验证通过后，请求token相关数据
     *
     * @param \Illuminate\Http\Request $request
     * @param mixed $user
     * @return mixed
     */
    protected function authenticated(Request $request, $user)
    {
        return (new TokenProxy())->proxy(
            'password',
            [
                'username' => $user->username,
                'password' => $request->input('password'),
                'scope' => ''
            ]
        );
    }

    /**
     * 登录表单元素名称
     *
     * @return string
     */
    public function username()
    {
        return 'account';
    }

    /**
     * 退出登录
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout(Request $request)
    {
        $user = $this->guard()->user();

        if ($user) {
            $user->token()->revoke();
        }

        return $this->loggedOut($request);
    }

    /**
     * 用户退出登录后
     *
     * @param \Illuminate\Http\Request $request
     * @return mixed
     */
    protected function loggedOut(Request $request)
    {
        return response()->json(
            [
                'status' => 'success',
                'message' => '退出成功'
            ]
        );
    }

    /**
     * 社会化登录
     *
     * @param Request $request
     * @param string $driver
     * @return bool
     */
    public function redirectToProvider(Request $request, $driver)
    {

        if (!in_array($driver, ['qq', 'wechat'])) {
            return false;
        }

        return \Socialite::driver($driver)
            ->scopes([$request->query('scopes', 'snsapi_userinfo')])
            ->with(['state' => urlencode($request->query('target_url'))])
            ->redirect();
    }

    /**
     * 社会化登陆回调
     *
     * @param Request $request
     * @param string $driver
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector
     */
    public function handleProviderCallback(Request $request, $driver)
    {
        $user = \Socialite::driver($driver)->user();
        if ($request->query('state')) {
            return redirect()->away(urldecode($request->query('state')) . '&openid=' . $user->id);
        } else {
            $unionid = '0';
            $db_user = User::where('openid->' . $driver . '->web', $user->id)->first();
            if (empty($db_user) and isset($user->original['unionid'])) {
                $unionid = $user->original['unionid'];
                $db_user = User::where('openid->' . $driver . '->unionid', $user->original['unionid'])->first();
            }
            if (empty($db_user)) {
                return redirect('bind/index/' . $driver . '/' . $user->id . '/' . $unionid . '/0');
            } else {
                $token = $db_user->createToken($user->id)->accessToken;
                $domain = config('settingSite.ssl') ? 'https://' : 'http://';
                $domain .= config('settingSite.wapDomain');
                $url = $domain . '/#/login/oauth?token=' . $token . '&auth_id=' . md5($token) . '&expires_in=31104000';
                return redirect()->away($url);
            }
        }
    }

    /**
     * app微信登陆回调
     *
     * @param Request $request
     * @return string
     */
    public function handleAppAuth(Request $request)
    {
        $db_user = User::where('openid->wechat->app', $request->query('openid'))->first();
        if (empty($db_user)) {
            $db_user = User::where('openid->wechat->unionid', $request->query('unionid'))->first();
        }
        if (empty($db_user)) {
            return url('bind/index/wechat/' . $request->query('openid') . '/' . $request->query('unionid')) . '/1';
        } else {
            $token = $db_user->createToken($request->query('openid'))->accessToken;
            $domain = config('settingSite.ssl') ? 'https://' : 'http://';
            $domain .= config('settingSite.wapDomain');
            return $domain . '/#/login/oauth?token=' . $token . '&auth_id=' . md5($token) . '&expires_in=31104000';
        }
    }
}