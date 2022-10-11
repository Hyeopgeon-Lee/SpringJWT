package kopo.poly.auth;

import io.jsonwebtoken.*;
import kopo.poly.dto.UserInfoDTO;
import kopo.poly.service.IUserInfoSsService;
import kopo.poly.util.CmmUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    @Value("${jwt.secret.key}")
    private String secretKey;

    @Value("${jwtw.token.creator}")
    private String creator;

    @Value("${jwt.token.access.valid.time}")
    private long accessTokenValidTime;

    @Value("${jwt.token.access.name}")
    private String accessTokenName;

    @Value("${jwt.token.refresh.valid.time}")
    private long refreshTokenValidTime;

    @Value("${jwt.token.refresh.name}")
    private String refreshTokenName;

    // Spring Security에서 정의한 loadUserByUsername함수가 존재하는 서비스 객체
    private final IUserInfoSsService userInfoSsService;

    /**
     * JWT 토큰(Access Token, Refresh Token)생성
     *
     * @param userId    회원 아이디(ex. hglee67)
     * @param roles     회원 권한
     * @param tokenType token 유형
     * @return 인증 처리한 정보(로그인 성공, 실패)
     */
    public String createToken(String userId, String roles, JwtTokenType tokenType) {

        log.info(this.getClass().getName() + ".createToken Start!");

        log.info("userId : " + userId);

        long validTime = 0;

        if (tokenType == JwtTokenType.ACCESS_TOKEN) { // Access Token이라면
            validTime = (accessTokenValidTime * 60 * 1000);

        } else if (tokenType == JwtTokenType.REFRESH_TOKEN) { // Refresh Token이라면
            validTime = (refreshTokenValidTime * 60 * 1000);

        }

        Claims claims = Jwts.claims()
                .setIssuer(creator) // JWT 토큰 생성자 기입함
                .setSubject(userId); // 회원아이디 저장 : PK 저장(userId)

        claims.put("roles", roles); // JWT Paylaod에 정의된 기본 옵션 외 정보를 추가 - 사용자 권한 추가
        Date now = new Date();

        log.info(this.getClass().getName() + ".createToken End!");

        // Builder를 통해 토큰 생성
        return Jwts.builder()
                .setClaims(claims) // 정보 저장
                .setIssuedAt(now) // 토큰 발행 시간 정보
                .setExpiration(new Date(now.getTime() + (validTime * 60 * 1000))) // set Expire Time
                .signWith(SignatureAlgorithm.HS256, secretKey)  // 사용할 암호화 알고리즘과
                .compact();
    }

    /**
     * JWT 토큰(Access Token, Refresh Token)에서 인증 정보 조회 및
     * 아이디, 패스워드가 맞다면, Spring Security를 통해 로그인처리하기
     *
     * @param token 토큰
     * @return 인증 처리한 정보(로그인 성공, 실패)
     */
    public Authentication getAuthentication(String token) {

        log.info(this.getClass().getName() + ".getAuthentication Start!");
        log.info("getAuthentication : " + token);

        // JWT 토큰에 저장된 사용자 아이디 : hglee67
        String userId = CmmUtil.nvl(getUserId(token));

        log.info("user_id : " + userId);

        // Spring Security에 적용한 loadUserByUsername 함수 호출하여 로그인 처리할 사용자 정보 가져오기
        AuthInfo info = (AuthInfo) userInfoSsService.loadUserByUsername(userId);

        UserInfoDTO dto = info.getUserInfoDTO();

        if (dto == null) {
            dto = new UserInfoDTO();
        }

        // DB에 저장된 사용자의 권한
        String roles = CmmUtil.nvl(dto.getRoles()); // 권한 가져오기

        Set<GrantedAuthority> pSet = new HashSet<>();
        if (roles.length() > 0) { //DB에 저장된 Role이 있는 경우에만 실행
            for (String role : roles.split(",")) {
                pSet.add(new SimpleGrantedAuthority(role));

            }
        }

        log.info(this.getClass().getName() + ".getAuthentication End!");

        // Spring Security가 아이디와 패스워드 맞는지 체크하기 위해 UsernamePasswordAuthenticationToken 생성
        return new UsernamePasswordAuthenticationToken(info, "", pSet);
    }

    /**
     * JWT 토큰(Access Token, Refresh Token)에서 회원 정보 추출
     *
     * @param token 토큰
     * @return 회원 아이디(ex. hglee67)
     */
    public String getUserId(String token) {

        log.info(this.getClass().getName() + ".getUserId Start!");

        String userId = CmmUtil.nvl(Jwts.parser().setSigningKey(secretKey)
                .parseClaimsJws(token).getBody().getSubject());
        log.info("userId : " + userId);

        log.info(this.getClass().getName() + ".getUserId End!");

        return userId;
    }

    /**
     * JWT 토큰(Access Token, Refresh Token)에서 회원 정보 추출
     *
     * @param token 토큰
     * @return 회원 아이디(ex. hglee67)
     */
    public String getUserRoles(String token) {

        log.info(this.getClass().getName() + ".getUserRoles Start!");
        String roles = CmmUtil.nvl((String) Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token)
                .getBody().get("roles"));

        log.info("roles : " + roles);

        log.info(this.getClass().getName() + ".getUserRoles End!");

        return roles;
    }

    /**
     * 쿠기에 저장된 JWT 토큰(Access Token, Refresh Token) 가져오기
     *
     * @param request   request 정보
     * @param tokenType token 유형
     * @return 쿠기에 저장된 토큰 값
     */
    public String resolveToken(HttpServletRequest request, JwtTokenType tokenType) {

        log.info(this.getClass().getName() + ".resolveToken Start!");

        String tokenName = "";

        if (tokenType == JwtTokenType.ACCESS_TOKEN) { // Access Token이라면
            tokenName = accessTokenName;

        } else if (tokenType == JwtTokenType.REFRESH_TOKEN) { // Refresh Token이라면
            tokenName = refreshTokenName;

        }

        String token = "";

        // Cookie에 저장된 데이터 모두 가져오기
        Cookie[] cookies = request.getCookies();

        if (cookies != null) { // Cookie가 존재하면, Cookie에서 토큰 값 가져오기
            for (Cookie key : request.getCookies()) {
                if (key.getName().equals(tokenName)) {
                    token = CmmUtil.nvl(key.getValue());
                    break;
                }
            }
        }

        log.info(this.getClass().getName() + ".resolveToken End!");
        return token;
    }

    /**
     * JWT 토큰(Access Token, Refresh Token) 상태 확인
     *
     * @param token 토큰
     * @return 상태정보(EXPIRED, ACCESS, DENIED)
     */
    public JwtStatus validateToken(String token) {

        if (token.length() > 0) {

            try {
                Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);

                // 토큰 만료여부 체크
                if (claims.getBody().getExpiration().before(new Date())) {
                    return JwtStatus.EXPIRED; // 기간 만료

                } else {
                    return JwtStatus.ACCESS; // 유효한 토큰
                }

            } catch (ExpiredJwtException e) {
                // 만료된 경우에는 refresh token을 확인하기 위해
                return JwtStatus.EXPIRED; // 혹시 몰라서 Exception으로 한번 더 체크 기간 만료

            } catch (JwtException | IllegalArgumentException e) {
                log.info("jwtException : {}", e);

                return JwtStatus.DENIED;
            }

        } else {
            return JwtStatus.DENIED;
        }

    }

}
