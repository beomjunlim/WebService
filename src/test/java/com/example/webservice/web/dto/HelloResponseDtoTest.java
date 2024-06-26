package com.example.webservice.web.dto;

import static org.assertj.core.api.Assertions.*;

import org.junit.jupiter.api.Test;

public class HelloResponseDtoTest {
    @Test
    public void lombokTest(){
        // given
        String name = "test";
        int amount = 1000;

        // when
        HelloResponseDto dto = new HelloResponseDto(name, amount);

        // then
        assertThat(dto.getName()).isEqualTo(name);
        assertThat(dto.getAmount()).isEqualTo(amount);
    }
}
