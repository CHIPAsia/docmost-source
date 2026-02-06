import { Menu, ActionIcon, Text } from "@mantine/core";
import React from "react";
import { IconDots, IconShieldOff, IconTrash } from "@tabler/icons-react";
import { modals } from "@mantine/modals";
import {
  useDeleteWorkspaceMemberMutation,
  useAdminDisableMfaMutation,
} from "@/features/workspace/queries/workspace-query.ts";
import { useTranslation } from "react-i18next";
import useUserRole from "@/hooks/use-user-role.tsx";

interface Props {
  userId: string;
  mfaEnabled?: boolean;
}
export default function MemberActionMenu({ userId, mfaEnabled = false }: Props) {
  const { t } = useTranslation();
  const deleteWorkspaceMemberMutation = useDeleteWorkspaceMemberMutation();
  const adminDisableMfaMutation = useAdminDisableMfaMutation();
  const { isAdmin, isOwner } = useUserRole();

  const onRevoke = async () => {
    await deleteWorkspaceMemberMutation.mutateAsync({ userId });
  };

  const openRevokeModal = () =>
    modals.openConfirmModal({
      title: t("Delete member"),
      children: (
        <Text size="sm">
          {t(
            "Are you sure you want to delete this workspace member? This action is irreversible.",
          )}
        </Text>
      ),
      centered: true,
      labels: { confirm: t("Delete"), cancel: t("Don't") },
      confirmProps: { color: "red" },
      onConfirm: onRevoke,
    });

  const onDisableMfa = async () => {
    await adminDisableMfaMutation.mutateAsync({ userId });
  };

  const openDisableMfaModal = () =>
    modals.openConfirmModal({
      title: t("Disable 2FA"),
      children: (
        <Text size="sm">
          {t(
            "Are you sure you want to disable two-factor authentication for this user? They will need to set it up again to re-enable.",
          )}
        </Text>
      ),
      centered: true,
      labels: { confirm: t("Disable 2FA"), cancel: t("Cancel") },
      confirmProps: { color: "orange" },
      onConfirm: onDisableMfa,
    });

  return (
    <>
      <Menu
        shadow="xl"
        position="bottom-end"
        offset={20}
        width={200}
        withArrow
        arrowPosition="center"
      >
        <Menu.Target>
          <ActionIcon variant="subtle" c="gray">
            <IconDots size={20} stroke={2} />
          </ActionIcon>
        </Menu.Target>

        <Menu.Dropdown>
          {mfaEnabled && isOwner && (
            <Menu.Item
              onClick={openDisableMfaModal}
              leftSection={<IconShieldOff size={16} />}
            >
              {t("Disable 2FA")}
            </Menu.Item>
          )}
          <Menu.Item
            c="red"
            onClick={openRevokeModal}
            leftSection={<IconTrash size={16} />}
            disabled={!isAdmin}
          >
            {t("Delete member")}
          </Menu.Item>
        </Menu.Dropdown>
      </Menu>
    </>
  );
}
