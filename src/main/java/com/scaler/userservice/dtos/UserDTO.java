package com.scaler.userservice.dtos;

import com.scaler.userservice.models.Role;
import com.scaler.userservice.models.User;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class UserDTO {
    private Long userId;
    private String name;
    private String email;
    private List<Role> roles;


    public static UserDTO from(User user){
        UserDTO userDTO = new UserDTO();
        userDTO.userId = user.getId();
        userDTO.name = user.getName();
        userDTO.roles = user.getRoles();
        userDTO.email = user.getEmail();
        return userDTO;
    }

}


