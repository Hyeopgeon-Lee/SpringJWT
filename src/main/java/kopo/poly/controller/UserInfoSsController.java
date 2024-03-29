package kopo.poly.controller;

import kopo.poly.auth.AuthInfo;
import kopo.poly.auth.JwtTokenProvider;
import kopo.poly.auth.JwtTokenType;
import kopo.poly.auth.UserRole;
import kopo.poly.dto.MsgDTO;
import kopo.poly.dto.UserInfoDTO;
import kopo.poly.service.IUserInfoSsService;
import kopo.poly.util.CmmUtil;
import kopo.poly.util.EncryptUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Optional;

@Slf4j
@RequestMapping(value = "/ss")
@RequiredArgsConstructor
@Controller
public class UserInfoSsController {

    @Value("${jwt.token.access.valid.time}")
    private long accessTokenValidTime;

    @Value("${jwt.token.access.name}")
    private String accessTokenName;

    @Value("${jwt.token.refresh.valid.time}")
    private long refreshTokenValidTime;

    @Value("${jwt.token.refresh.name}")
    private String refreshTokenName;

    private final JwtTokenProvider jwtTokenProvider;

    // 생성자를 통해 스프링 시작할 때, 메모리에 저장된 객체를 데이터타입에 맞춰 저장하기
    // @Service 어노테이션을 통해 스프링 시작할 때, IUserInfoService 객체가 메모리에 저장됨
    private final IUserInfoSsService userInfoSsService;

    // Spring Security에서 제공하는 비밀번호 암호화 객체(해시 함수)
    private final PasswordEncoder bCryptPasswordEncoder;

    /**
     * 회원가입 화면으로 이동
     */
    @GetMapping(value = "userRegForm")
    public String userRegForm() {
        log.info(this.getClass().getName() + ".userRegForm Start!");

        log.info(this.getClass().getName() + ".userRegForm End!");

        return "ss/userRegForm";
    }

    /**
     * 회원 가입 전 아이디 중복체크하기(Ajax를 통해 입력한 아이디 정보 받음)
     */
    @ResponseBody
    @PostMapping(value = "getUserIdExists")
    public UserInfoDTO getUserExists(HttpServletRequest request) throws Exception {

        log.info(this.getClass().getName() + ".getUserIdExists Start!");

        String userId = CmmUtil.nvl(request.getParameter("userId")); // 회원아이디

        log.info("userId : " + userId);

        UserInfoDTO pDTO = new UserInfoDTO();
        pDTO.setUserId(userId);

        // 회원아이디를 통해 중복된 아이디인지 조회
        UserInfoDTO rDTO = Optional.ofNullable(userInfoSsService.getUserIdExists(pDTO)).orElseGet(UserInfoDTO::new);

        log.info(this.getClass().getName() + ".getUserIdExists End!");

        return rDTO;
    }

    /**
     * 회원가입 로직 처리
     */
    @ResponseBody
    @PostMapping(value = "insertUserInfo")
    public MsgDTO insertUserInfo(HttpServletRequest request) {

        log.info(this.getClass().getName() + ".insertUserInfo start!");

        int res = 0; // 회원가입 결과
        String msg = ""; //회원가입 결과에 대한 메시지를 전달할 변수
        MsgDTO dto = null; // 결과 메시지 구조

        //웹(회원정보 입력화면)에서 받는 정보를 저장할 변수
        UserInfoDTO pDTO = null;

        try {

            String userId = CmmUtil.nvl(request.getParameter("userId")); //아이디
            String userName = CmmUtil.nvl(request.getParameter("userName")); //이름
            String password = CmmUtil.nvl(request.getParameter("password")); //비밀번호
            String email = CmmUtil.nvl(request.getParameter("email")); //이메일
            String addr1 = CmmUtil.nvl(request.getParameter("addr1")); //주소
            String addr2 = CmmUtil.nvl(request.getParameter("addr2")); //상세주소

            log.info("userId : " + userId);
            log.info("userName : " + userName);
            log.info("password : " + password);
            log.info("email : " + email);
            log.info("addr1 : " + addr1);
            log.info("addr2 : " + addr2);

            //웹(회원정보 입력화면)에서 받는 정보를 저장할 변수를 메모리에 올리기
            pDTO = new UserInfoDTO();

            pDTO.setUserId(userId);
            pDTO.setUserName(userName);

            //비밀번호는 Spring Security에서 제공하는 해시 암호화 수행
            pDTO.setPassword(bCryptPasswordEncoder.encode(password));

            //민감 정보인 이메일은 AES128-CBC로 암호화함
            pDTO.setEmail(EncryptUtil.encAES128CBC(email));
            pDTO.setAddr1(addr1);
            pDTO.setAddr2(addr2);

            // 권한 부여(사용자)
            pDTO.setRoles(UserRole.USER.getValue());

            // 권한 부여(관리자)
//            pDTO.setRoles(UserRole.ADMIN.getValue());

            /*
             * 회원가입
             * */
            res = userInfoSsService.insertUserInfo(pDTO);

            log.info("회원가입 결과(res) : " + res);

            if (res == 1) {
                msg = "회원가입되었습니다.";

                //추후 회원가입 입력화면에서 ajax를 활용해서 아이디 중복, 이메일 중복을 체크하길 바람
            } else if (res == 2) {
                msg = "이미 가입된 아이디입니다.";

            } else {
                msg = "오류로 인해 회원가입이 실패하였습니다.";

            }

        } catch (Exception e) {
            //저장이 실패되면 사용자에게 보여줄 메시지
            msg = "실패하였습니다. : " + e;
            log.info(e.toString());
            e.printStackTrace();

        } finally {
            // 결과 메시지 전달하기
            dto = new MsgDTO();
            dto.setResult(res);
            dto.setMsg(msg);

            log.info(this.getClass().getName() + ".insertUserInfo End!");

        }

        return dto;
    }

    /**
     * 로그인을 위한 입력 화면으로 이동
     */
    @GetMapping(value = "login")
    public String login() {
        log.info(this.getClass().getName() + "login Start!");

        log.info(this.getClass().getName() + ".login End!");

        return "ss/login";
    }

    @ResponseBody
    @RequestMapping(value = "loginSuccess")
    public MsgDTO loginSuccess(@AuthenticationPrincipal AuthInfo authInfo,
                               HttpServletResponse response, ModelMap model) {

        log.info(this.getClass().getName() + ".loginSuccess Start!");

        // Spring Security에 저장된 정보 가져오기
        UserInfoDTO rDTO = Optional.ofNullable(authInfo.getUserInfoDTO()).orElseGet(UserInfoDTO::new);

        String userId = CmmUtil.nvl(rDTO.getUserId());
        String userName = CmmUtil.nvl(rDTO.getUserName());
        String userRoles = CmmUtil.nvl(rDTO.getRoles());

        log.info("userId : " + userId);
        log.info("userName : " + userName);
        log.info("userRoles : " + userRoles);

        // Access Token 생성
        String accessToken = jwtTokenProvider.createToken(userId, userRoles, JwtTokenType.ACCESS_TOKEN);

        ResponseCookie cookie = ResponseCookie.from(accessTokenName, accessToken)
                .domain("localhost")
                .path("/")
//                .secure(true)
//                .sameSite("None")
                .maxAge(accessTokenValidTime) // JWT Refresh Token 만료시간 설정
                .httpOnly(true)
                .build();

        // 기존 쿠기 모두 삭제하고, Cookie에 Access Token 저장하기
        response.setHeader("Set-Cookie", cookie.toString());

        cookie = null;

        // Refresh Token 생성
        // Refresh Token은 보안상 노출되면, 위험하기에 Refresh Token은 DB에 저장하고,
        // DB를 조회하기 위한 값만 Refresh Token으로 생성함
        // 본 실습은 DB에 저장하지 않고, 사용자 컴퓨터의 쿠키에 저장함
        // Refresh Token은 Access Token에 비해 만료시간을 길게 설정함
        String refreshToken = jwtTokenProvider.createToken(userId, userRoles, JwtTokenType.REFRESH_TOKEN);

        cookie = ResponseCookie.from(refreshTokenName, refreshToken)
                .domain("localhost")
                .path("/")
//                .secure(true)
//                .sameSite("None")
                .maxAge(refreshTokenValidTime) // JWT Refresh Token 만료시간 설정
                .httpOnly(true)
                .build();

        // 기존 쿠기에 Refresh Token 저장하기
        response.addHeader("Set-Cookie", cookie.toString());

        // 결과 메시지 전달하기
        MsgDTO dto = new MsgDTO();
        dto.setResult(1);
        dto.setMsg(userName + "님 로그인이 성공하였습니다.");

        // JSP에 값 전달하기
        model.addAttribute("userName", userName);

        log.info(this.getClass().getName() + ".loginSuccess End!");

        return dto;
    }

    @ResponseBody
    @RequestMapping(value = "loginFail")
    public MsgDTO loginFail() {

        log.info(this.getClass().getName() + ".loginFail Start!");

        // 결과 메시지 전달하기
        MsgDTO dto = new MsgDTO();
        dto.setResult(0);
        dto.setMsg("로그인이 실패하였습니다.");

        log.info(this.getClass().getName() + ".loginFail End!");

        return dto;

    }

    @ResponseBody
    @RequestMapping(value = "logoutSuccess")
    public MsgDTO logoutSuccess() {

        log.info(this.getClass().getName() + ".logoutSuccess Start!");

        // 결과 메시지 전달하기
        MsgDTO dto = new MsgDTO();
        dto.setResult(0);
        dto.setMsg("로그아웃 되었습니다.");

        log.info(this.getClass().getName() + ".logoutSuccess End!");

        return dto;

    }

}
