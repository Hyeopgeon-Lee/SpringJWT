package kopo.poly.service;

import kopo.poly.dto.UserInfoDTO;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface IUserInfoSsService extends UserDetailsService {

    /**
     * 회원가입할 떄, 회원아이디 중복 여부 체크를 위해 사용됨
     *
     * @param pDTO 중복체크할 회원아이디 정보
     */
    UserInfoDTO getUserIdExists(UserInfoDTO pDTO) throws Exception;

    /**
     * 회원 가입하기(회원정보 등록하기)
     *
     * @param pDTO HTML로부터 받은 회원가입 정보
     */
    int insertUserInfo(UserInfoDTO pDTO) throws Exception;

}
