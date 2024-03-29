package kopo.poly.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserInfoDTO {

    private String userId;
    private String userName;
    private String password;
    private String email;
    private String addr1;
    private String addr2;
    private String regId;
    private String regDt;
    private String chgId;
    private String chgDt;
    private String roles;

    // 회원가입시, 중복가입을 방지 위해 사용할 변수
    // DB 조회해서 회원이 존재하면 Y값을 반환함
    // DB 테이블에 존재하지 않는 가상의 컬럼(ALIAS)
    private String existsYn;


}

