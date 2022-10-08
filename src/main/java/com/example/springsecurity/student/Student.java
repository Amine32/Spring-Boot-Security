package com.example.springsecurity.student;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class Student {

    private final Integer studentId;

    private final String studentName;
}
