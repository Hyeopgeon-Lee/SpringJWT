package kopo.poly.auth;

import io.jsonwebtoken.*;
import kopo.poly.dto.TokenDTO;
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
import java.util.Optional;
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
            validTime = (accessTokenValidTime);

        } else if (tokenType == JwtTokenType.REFRESH_TOKEN) { // Refresh Token이라면
            validTime = (refreshTokenValidTime);

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
                .setExpiration(new Date(now.getTime() + (validTime * 1000))) // set Expire Time
                .signWith(SignatureAlgorithm.HS256, secretKey)  // 사용할 암호화 알고리즘과
                .compact();
    }

    /**
     * JWT 토큰(Access Token, Refresh Token)에 저장된 값 가져오기
     *
     * @param token 토큰
     * @return 회원 아이디(ex. hglee67)
     */
    public TokenDTO getTokenInfo(String token) {

        log.info(this.getClass().getName() + ".getTokenInfo Start!");

        // JWT 토큰 정보
        Claims claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();

        String userId = CmmUtil.nvl(claims.getSubject());
        String role = CmmUtil.nvl((String) claims.get("roles")); // LoginService 생성된 토큰의 권한명과 동일

        log.info("userId : " + userId);
        log.info("role : " + role);

        TokenDTO pDTO = new TokenDTO();

        pDTO.setUserId(userId);
        pDTO.setRole(role);

        log.info(this.getClass().getName() + ".getTokenInfo End!");

        return pDTO;
    }

    /**
     * 매 요청마다 JWT 토큰(Access Token, Refresh Token)으로부터 받은 아이디, 권한 정보를
     * Spring Security 인증 정보에 넣어 권한에 맞게 접근 제어하도록 처리함
     *
     * @param token 토큰
     * @return 인증 처리한 정보(로그인 성공, 실패)
     */
    public Authentication getAuthentication(String token) {

        log.info(this.getClass().getName() + ".getAuthentication Start!");
        log.info("getAuthentication : " + token);

        // 토큰에 저장된 정보가져오기
        TokenDTO tokenInfo = Optional.ofNullable(getTokenInfo(token)).orElseGet(TokenDTO::new);

        // JWT 토큰에 저장된 사용자 아이디 : hglee67
        String userId = CmmUtil.nvl(tokenInfo.getUserId());

        log.info("user_id : " + userId);

        // Spring Security에 적용한 loadUserByUsername 함수 호출하여 회원 DB에 존재하는지 체크
        // 회원이 존재하면, 인증 정보 생성함
        AuthInfo info = (AuthInfo) userInfoSsService.loadUserByUsername(userId);

        // AuthInfo 객체에 저장된 회원정보가져오기
        UserInfoDTO dto = Optional.ofNullable(info.getUserInfoDTO()).orElseGet(UserInfoDTO::new);

        // 회원정보 DB에 저장된 사용자의 권한을 가져오기(1명이 여러 권한을 가질 수 있으며 권한 구분자는 ,)
        String roles = CmmUtil.nvl(dto.getRoles()); // 권한 예 : ROLE_ADMIN, ROLE_USER

        Set<GrantedAuthority> pSet = new HashSet<>(); // 1명이 여러 권한을 가질 수 있으며, 중복권한이 안되게 Set 구조 사용

        if (roles.length() > 0) { // DB에 저장된 Role이 있는 경우에만 실행
            for (String role : roles.split(",")) { //여러 권한의 구분자 ,
                pSet.add(new SimpleGrantedAuthority(role)); // 권한 저장하기

            }
        }

        log.info(this.getClass().getName() + ".getAuthentication End!");

        // JWT 토큰에 저장된 권한에 맞춰 Spring Security가 권한 체크하도록 Filter 호출
        return new UsernamePasswordAuthenticationToken(info, "", pSet);
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
