package com.pjb.springbootjjwt.interceptor;

import cn.hutool.json.JSONUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.pjb.springbootjjwt.annotation.PassToken;
import com.pjb.springbootjjwt.annotation.UserLoginToken;
import com.pjb.springbootjjwt.entity.User;
import com.pjb.springbootjjwt.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.HandlerMethod;

import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;
import java.util.List;


/**
 * @author jinbin
 * @date 2018-07-08 20:41
 * 拦截器，拦截验证token
 */
public class AuthenticationInterceptor implements HandlerInterceptor {
    @Autowired
    UserService userService;

    @Override
    public boolean preHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object object) throws Exception {
        // 从 http 请求头中取出 token
        String token = httpServletRequest.getHeader("token");
        // 如果不是映射到方法直接通过
        if (!(object instanceof HandlerMethod)) {
            return true;
        }

        HandlerMethod handlerMethod = (HandlerMethod) object;
        Method method = handlerMethod.getMethod();
        //检查是否有@passtoken注解，有则跳过认证
        if (method.isAnnotationPresent(PassToken.class)) {
            PassToken passToken = method.getAnnotation(PassToken.class);
            if (passToken.required()) {
                return true;
            }
        }
        //弄掉下面的注解就是需要有@UserLoginToken注解的接口才要被校验，不弄掉就是所有的接口都要被校验
        //检查有没有需要用户权限的注解
      //  if (method.isAnnotationPresent(UserLoginToken.class)) {
          //  UserLoginToken userLoginToken = method.getAnnotation(UserLoginToken.class);
           // if (userLoginToken.required()) {
                // 执行认证
                if (token == null) {
                    throw new RuntimeException("无token，请重新登录");
                }
                // 获取 token 中的 user id,进行数据库查询
                String userId;
                try {
                    //获取token中携带的数据，为一个list列表
                    List<String> audience = JWT.decode(token).getAudience();
                    //糊涂工具json字符串转对象
                    User user = JSONUtil.toBean(audience.get(0), User.class);
                    System.out.println(user);
                    System.out.println(JWT.decode(token).getAudience());
                    System.out.println(JWT.decode(token).getAudience().get(0));
                    userId = JWT.decode(token).getAudience().get(0);
                } catch (JWTDecodeException j) {
                    throw new RuntimeException("401,token错误");
                }
                //查找数据库判断用户是否存在
                //User user = userService.findUserById(userId);
                User user = new User("1", "zgr", "zgr1234");
                if (user == null) {
                    throw new RuntimeException("用户不存在，请重新登录");
                }
                // 验证 token，用密码作为秘钥
                JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(user.getPassword())).build();
                try {
                    //校验token
                    jwtVerifier.verify(token);
                } catch (JWTVerificationException e) {
                    throw new RuntimeException("401，token不正确");
                }
                return true;
         //   }
        //}
      //  return true;
    }

    @Override
    public void postHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object o, ModelAndView modelAndView) throws Exception {

    }

    @Override
    public void afterCompletion(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object o, Exception e) throws Exception {

    }
}
