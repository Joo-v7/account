package com.chokchok.accountapi.domain.member;

import com.chokchok.accountapi.common.exception.base.InvalidEnumValueException;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum Gender {
    MALE("남성"),
    FEMALE("여성"),
    OTHER("기타");

    private final String displayName;

    Gender(String displayName) {
        this.displayName = displayName;
    }

    @JsonValue
    public String getDisplayName() {
        return displayName;
    }

    @JsonCreator
    public static Gender fromDisplayName(String displayName) {
        for (Gender gender : Gender.values()) {
            if (gender.displayName.equals(displayName)) {
                return gender;
            }
        }
        throw new InvalidEnumValueException("gender 값이 올바르지 않습니다");
    }

}
