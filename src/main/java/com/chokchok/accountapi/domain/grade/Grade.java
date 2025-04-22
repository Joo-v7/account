package com.chokchok.accountapi.domain.grade;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * id | name   | accumulation_rate | description
 * 1  | BASIC  | 1                 | 결제 시 순수금액의 1% 포인트 적립
 * 2  | SILVER | 3                 | 결제 시 순수금액의 3% 포인트 적립
 * 3  | GOLD   | 5                 | 결제 시 순수금액의 5% 포인트 적립
 * 4  | VIP    | 7                 | 결제 시 순수금액의 7% 포인트 적립
 */

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Table(name="grades")
@Entity
public class Grade {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(unique = true, nullable = false, length = 10)
    private String name;

    @Column(nullable = false)
    private Integer accumulationRate;

    @Column(nullable = false)
    private String description;

    private Grade(String name, Integer accumulationRate, String description) {
        this.name = name;
        this.accumulationRate = accumulationRate;
        this.description = description;
    }

    public static Grade create(String name, Integer accumulationRate, String description) {
        return new Grade(name, accumulationRate, description);
    }

}
