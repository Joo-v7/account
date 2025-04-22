package com.chokchok.accountapi.repository.role;

import com.chokchok.accountapi.domain.role.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Integer> {
}
