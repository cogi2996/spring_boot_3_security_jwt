package com.example.security.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.example.security.user.Permission.*;

@RequiredArgsConstructor
public enum Role {
    USER(Collections.emptySet()),
    ADMIN(
            Set.of(
                    ADMIN_READ,
                    ADMIN_CREATE,
                    ADMIN_DELETE,
                    ADMIN_UPDATE,
                    MANAGER_READ,
                    MANAGER_CREATE,
                    MANAGER_DELETE,
                    MANAGER_UPDATE
            )
    ),
    MANAGER(
            Set.of(
                    MANAGER_READ,
                    MANAGER_CREATE,
                    MANAGER_DELETE,
                    MANAGER_UPDATE
            )
    )
    ;
    @Getter
    private final Set<Permission> permissions;
    // trả về danh sách quyền của user
    public List<SimpleGrantedAuthority> getAuthorities() {
        var authorities = permissions.stream()
                // map to permission
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                // collect to list
                .collect(Collectors.toList());
        // khi spring Làm việc với role phải có prefix ROLE_
        authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return authorities;
    }
}
