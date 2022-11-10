package authentic

import (
	"context"
	"encoding/json"
	"github.com/gogf/gf/v2/container/gvar"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gcache"
	"github.com/gogf/gf/v2/util/grand"
	"github.com/golang-jwt/jwt/v4"
	"github.com/hinego/errorx"
	"time"
)

type Authentic struct {
	Expire     time.Duration          //默认有效时间
	Key        string                 //默认Key
	Methods    map[string]string      //获取token的规则
	HeaderName string                 //header标头
	Method     jwt.SigningMethod      //算法
	Secret     []byte                 //私钥
	Cache      *gcache.Cache          //用于保存key
	AddCode    func(c *Context) error //登录时向数据库写入token
	SetCode    func(c *Context) error //刷新过期时间
	DelCode    func(c *Context) error //退出登录时更新数据
	LoadCode   func(c *Context) error
}

// authentic
var (
	TokenRaw = "JWT_TOKEN_Raw"
	Token    = "JWT_TOKEN"
	Payload  = "JWT_PAYLOAD"
)

type Context struct {
	Cache   *gcache.Cache
	Context context.Context
	Token   *jwt.Token
	Expire  time.Time
	Data    map[string]any
}

func (r *Authentic) Init() error {
	if int64(r.Expire) == 0 {
		r.Expire = 720 * time.Hour
	}
	if r.Key == "" {
		r.Key = "id"
	}
	if r.Methods == nil {
		r.Methods = map[string]string{
			"header": "Authorization",
			"query":  "token",
			"cookie": "jwt",
		}
	}
	if r.HeaderName == "" {
		r.HeaderName = "Bearer"
	}
	if r.Method == nil {
		r.Method = jwt.SigningMethodHS256
	}
	if r.Secret == nil {
		r.Secret = []byte("~~~~~~~~~~22asd~~~~~~1234f")
	}
	if r.Cache == nil {
		r.Cache = gcache.New()
	}
	return r.LoadCode(&Context{
		Cache:   r.Cache,
		Context: context.TODO(),
	})
}
func (r *Authentic) parse(ctx context.Context) (*jwt.Token, error) {
	req := g.RequestFromCtx(ctx)
	var token string
	var err error
	for k, v := range r.Methods {
		if len(token) > 0 {
			break
		}
		switch k {
		case "header":
			token, err = getTokenFromHeader(req, v, r.HeaderName)
		case "query":
			token, err = getTokenFormQuery(req, v)
		case "cookie":
			token, err = getTokenFormCookie(req, v)
		}
	}
	if err != nil {
		return nil, err
	}
	req.SetParam(TokenRaw, token)
	return jwt.Parse(token, r.keyFunc)
}
func (r *Authentic) keyFunc(t *jwt.Token) (interface{}, error) {
	if r.Method != t.Method {
		return nil, ErrInvalidSigningAlgorithm
	}
	return r.Secret, nil
}
func (r *Authentic) CreateToken(ctx context.Context, data map[string]any) (*Context, error) {
	var err error
	var code string
	token := jwt.New(r.Method)
	claims := token.Claims.(jwt.MapClaims)
	for key, value := range data {
		claims[key] = value
	}
	if _, ok := claims[r.Key]; !ok {
		return nil, errorx.NewCode(500, ErrMissingIdentity, nil)
	}
	expire := time.Now().Add(r.Expire)
	claims["r"] = grand.Letters(8)
	if code, err = token.SignedString(r.Secret); err != nil {
		return nil, errorx.NewCode(401, ErrFailedTokenCreation, nil)
	}
	token.Raw = code
	c := &Context{
		Cache:   r.Cache,
		Context: ctx,
		Token:   token,
		Expire:  expire,
		Data:    data,
	}
	if err = r.AddCode(c); err != nil {
		return nil, err
	}
	data["expire"] = expire.Unix()
	if err = r.Cache.Set(ctx, token.Raw, data, expire.Sub(time.Now())); err != nil {
		return nil, err
	}
	return c, nil
}
func (r *Authentic) LoginHandler(ctx context.Context, data map[string]any) error {
	if token, err := r.CreateToken(ctx, data); err != nil {
		return err
	} else {
		ret := map[string]any{
			"expire": token.Expire.Unix(),
			"token":  token.Token.Raw,
		}
		return errorx.NewCode(0, "success", ret)
	}
}
func (r *Authentic) middleware(request *ghttp.Request, fun func(data map[string]any) bool) {
	var token *jwt.Token
	var err error
	var get *gvar.Var
	if token, err = r.parse(request.GetCtx()); err != nil {
		request.SetError(errorx.NewCode(500, err, nil))
		return
	}
	var data = map[string]any{}
	if get, err = r.Cache.Get(request.GetCtx(), token.Raw); err != nil {
		request.SetError(errorx.NewCode(500, err, nil))
		return
	} else {
		if !get.Bool() {
			request.SetError(errorx.NewCode(401, ErrInvalidToken, nil))
			return
		}
		if err := json.Unmarshal(get.Bytes(), &data); err != nil {
			request.SetError(errorx.NewCode(401, err, nil))
			return
		}
	}
	payload := token.Claims.(jwt.MapClaims)
	if fun != nil && !fun(payload) {
		request.SetError(errorx.NewCode(401, ErrForbidden, nil))
		return
	}
	request.SetParam(Payload, payload)
	request.SetParam(r.Key, payload[r.Key])
	request.SetParam(TokenRaw, token.Raw)
	request.SetParam(Token, token)
	request.Middleware.Next()
}
func (r *Authentic) Middleware(request *ghttp.Request) {
	r.middleware(request, nil)
}
func (r *Authentic) MiddlewareWithOption(fun func(data map[string]any) bool) func(request *ghttp.Request) {
	return func(request *ghttp.Request) {
		r.middleware(request, fun)
	}
}
func (r *Authentic) LogoutHandler(ctx context.Context) error {
	var err error
	t := g.RequestFromCtx(ctx).GetParam(Token).Interface()
	token := t.(*jwt.Token)
	if err = r.DelCode(&Context{
		Cache:   r.Cache,
		Context: ctx,
		Token:   token,
	}); err != nil {
		return err
	}
	if _, err := r.Cache.Remove(ctx, token.Raw); err != nil {
		return err
	}
	return errorx.NewCode(0, "Success", nil)
}
func (r *Authentic) RefreshHandler(ctx context.Context) error {
	var err error
	t := g.RequestFromCtx(ctx).GetParam(Token).Interface()
	token := t.(*jwt.Token)
	expire := time.Now().Add(r.Expire)
	if err = r.SetCode(&Context{
		Cache:   r.Cache,
		Context: ctx,
		Token:   token,
		Expire:  expire,
	}); err != nil {
		return err
	}
	var data = map[string]any{}
	if get, err := r.Cache.Get(ctx, token.Raw); err != nil {
		return err
	} else if err := json.Unmarshal(get.Bytes(), &data); err != nil {
		return err
	}
	data["expire"] = expire.Unix()
	if err := r.Cache.Set(ctx, token.Raw, data, expire.Sub(time.Now())); err != nil {
		return err
	}
	ret := map[string]any{
		"expire": expire.Unix(),
	}
	return errorx.NewCode(0, "refresh success", ret)
}
