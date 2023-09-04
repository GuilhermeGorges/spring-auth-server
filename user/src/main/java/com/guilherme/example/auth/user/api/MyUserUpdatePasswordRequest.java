package com.guilherme.example.auth.user.api;

import jakarta.validation.constraints.NotBlank;

public class MyUserUpdatePasswordRequest {

    @NotBlank
    private String password;

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
