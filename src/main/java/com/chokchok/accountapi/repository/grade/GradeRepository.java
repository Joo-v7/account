package com.chokchok.accountapi.repository.grade;

import com.chokchok.accountapi.domain.grade.Grade;
import org.springframework.data.jpa.repository.JpaRepository;

public interface GradeRepository extends JpaRepository<Grade, Integer> {
}
