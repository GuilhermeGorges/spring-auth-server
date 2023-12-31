package com.guilherme.example.auth.user.api;

import com.guilherme.example.auth.user.domain.UserEntity;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public class UserRequest {
    @NotBlank
    private String name;
    @NotBlank
    private String email;
    @NotBlank
    private String password;
    @NotNull
    private UserEntity.Type type;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public UserEntity.Type getType() {
        return type;
    }

    public void setType(UserEntity.Type type) {
        this.type = type;
    }

    public UserEntity toEntity() {    
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String encryptedPassword = passwordEncoder.encode(this.password);

        return new UserEntity(
                this.name,
                this.email,
                encryptedPassword,
                this.type
        );
    }
}
