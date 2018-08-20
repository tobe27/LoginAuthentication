package controller;

import exception.LoginException;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;
import model.User;
import service.UserService;
import util.CookieUtil;
import util.JwtUtil;
import util.Md5Util;
import util.XmemcachedManager;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * 注册登录登出
 */
@Controller
@RequestMapping
public class LoginController {
    @Autowired
    UserService userService;
    @Autowired
    XmemcachedManager xmemcachedManager;
    private Logger log = Logger.getLogger(LoginController.class);
    private static final long EXP = 60*60*1000; //token有效期60min
    private static final String REG = "^[a-zA-Z][a-zA-Z0-9_]*$"; //正则表达式.英文、数字、下划线，且英文开头
    private static final String INT = "^[0-9]*$"; //正则表达式.数字
    private static final String PHONE = "^1[3|5|7|8][0-9]{9}$"; //正则表达式.必须1开头的电话号码
    private static final String E_MAIL = "^[a-zA-Z0-9_]+@[a-zA-Z]+(\\.[a-zA-Z]+)+$"; //正则表达式.邮箱格式的正则表达式，格式必须为example@example.com

    @RequestMapping(value = "register" ,method = RequestMethod.GET)
    public ModelAndView registerPage(@ModelAttribute("user") User user){
        log.info("跳转到注册详情页");
        return new ModelAndView("register");
    }

    //注册成功后跳转到登录页面
    @RequestMapping(value = "/register",method = RequestMethod.POST)
    public ModelAndView register(@Validated User user) throws Exception {
        log.info("开始注册，并跳转");
        ModelAndView modelAndView = new ModelAndView();

        //判断不为空
        if(user.getName().isEmpty()||user.getPassword().isEmpty()||user.getQq().isEmpty()
                ||user.getPhoneNum().isEmpty()||user.getEmail().isEmpty()){
            log.info("注册信息为空，重新注册");
            throw new LoginException("注册信息不能为空，请重新注册");
        }
        //判断用户名匹配规则
        if(!user.getName().matches(REG)){
            throw new LoginException("注册用户名只能为英文、数字、下划线，且必须英文开头");
        }
        //判断用户名长度
        if(user.getName().length()>15){
            throw new LoginException("注册用户名称字符应不多于15个");
        }
        //判断是否用户名已存在
        if (userService.getUserByName(user.getName()) != null) {
            throw new LoginException("注册用户名已存在，请重新注册：" + user.getName());
        }
        //判断密码长度
        if(user.getPassword().length()<6||user.getPassword().length()>16){
            throw new LoginException("密码过短或过长，请设置6-16位密码");
        }
        //判断qq号码规则
        if(!user.getQq().matches(INT) || (user.getQq().length()<8||user.getQq().length()>13) ){
            throw new LoginException("QQ号码必须是8-13位数字，请输入有效的QQ号码");
        }
        //判断邮箱规则
        if(!user.getEmail().matches(E_MAIL)){
            throw new LoginException("输入邮箱不符合格式!只能使用英文、数字、下划线、@，如：e_mail@example.com.cn");
        }
        //判断手机规则
        if(!user.getPhoneNum().matches(PHONE)){
            throw  new LoginException("手机号码必须是1开头的有效的手机号码");
        }
        //获取验证码，验证通过后存入数据库，注册成功
        if (null != xmemcachedManager.get("code")) {
            log.info("从缓存中获取验证码:"+xmemcachedManager.get("code"));
            if (xmemcachedManager.get("code").equals(user.getCode())) {
                //MD5加盐加密
                user.setPassword(Md5Util.createSaltMd5(user.getPassword()));
                //默认头像
                user.setCode("https://lichunyu1234.oss-cn-shanghai.aliyuncs.com/ant.png?x-oss-process=image/resize,m_lfit,h_200,w_200");
                user.setCreatedAt(String.valueOf(System.currentTimeMillis()));
                try {
                    userService.addUser(user);
                    log.info("添加注册用户到数据库成功");
                } catch (Exception e) {
                    log.info("注册异常:" + e.getMessage());
                    throw new LoginException("数据异常，请尝试重新注册");
                }
                modelAndView.setViewName("login");
                log.info("注册成功，跳转到登录界面");
            } else {
                throw new LoginException("验证码不正确，请重新输入");
            }
        } else {
            throw new LoginException("没有找到验证码，请重新获取");
        }
        return modelAndView;
    }

    //登录页面
    @RequestMapping(value = "/login",method = RequestMethod.GET)
    public ModelAndView loginPage(@ModelAttribute("user") User user){
        log.info("跳转到登录页面");
        return new ModelAndView("login");
    }

    //登录跳转到首页
    @RequestMapping(value = "/login",method = RequestMethod.POST)
    public ModelAndView login(@Validated User user, HttpServletResponse response) throws Exception {
        log.info("开始登录");
        ModelAndView modelAndView = new ModelAndView();
        //登录判断不为空
        if (user.getName().isEmpty() || user.getPassword().isEmpty()){
            throw new LoginException("用户名或密码不能为空！");
        }
        //判断用户名是否已存在
        User user1 = userService.getUserByName(user.getName());
        if (user1 == null){
            throw new LoginException("用户名或密码不正确，请重新登录！");
        }
        //登录成功跳转到首页
        if(Md5Util.verifySaltMd5(user.getPassword(),user1.getPassword())){
            Map<String,Object> payload = new HashMap<>();
            payload.put("id",user1.getId());
            payload.put("exp",System.currentTimeMillis()+EXP);
            String token = new JwtUtil().createJwt(payload);
            CookieUtil.addCookie(response,"token",token);
            modelAndView.setViewName("redirect:/home"); //重定向到首页
            log.info("登录成功，跳转到首页");
        }else {
            log.info("密码不正确");
            throw new LoginException("用户名或密码不正确,请重新登录");
        }
        return modelAndView;
    }

    //退出登录
    @RequestMapping(value = "logout", method = RequestMethod.GET)
    public ModelAndView logout(HttpServletResponse response){
        log.info("退出登录");
        ModelAndView modelAndView = new ModelAndView();
        CookieUtil.removeCookie(response,"token");
        modelAndView.setViewName("redirect:/login");
        log.info("退出到登录页面");
        return modelAndView;
    }
}
