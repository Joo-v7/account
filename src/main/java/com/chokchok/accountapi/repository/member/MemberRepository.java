package com.chokchok.accountapi.repository.member;

import com.chokchok.accountapi.domain.member.Member;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, Long> {
}
